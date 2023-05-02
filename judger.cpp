#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>
using namespace std;
using ll = long long;
using json = nlohmann::json;

#define ERREXIT(msg)        \
    do {                    \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (false)

void write_file(std::string fn, std::string content) {
    std::ofstream st(fn);
    if (!st) {
        cerr << "Error writing to " << fn << endl;
        ERREXIT("write");
    }
    st << content;
    st.close();
}

std::string read_file(std::string fn) {
    std::ifstream st(fn);
    if (!st) {
        cerr << "Error reading " << fn << endl;
        ERREXIT("read");
    }
    std::stringstream ss;
    ss << st.rdbuf();
    return ss.str();
}

std::string read_file_empty(std::string fn) {
    std::ifstream st(fn);
    if (!st) {
        return "";
    }
    std::stringstream ss;
    ss << st.rdbuf();
    return ss.str();
}

string get_key(string s, string k) {
    stringstream ss(s);
    string kk, vv;
    while (ss >> kk >> vv) {
        if (kk == k) return vv;
    }
    return "err";
}

int uidpipe[2];

json read_json(string fn) {
    ifstream st(fn);
    json j;
    st >> j;
    return j;
}

void create_sandbox(string rootfs, string target, string size) {
    auto data = "mode=0777,size=" + size;
    if (mount(rootfs.c_str(), target.c_str(), "", MS_BIND, ""))
        ERREXIT("mount");
    if (mount("", target.c_str(), "", MS_REMOUNT | MS_RDONLY | MS_BIND, ""))
        ERREXIT("mount");
    if (mount("tmpfs", (target + "/tmp").c_str(), "tmpfs", 0, data.c_str()))
        ERREXIT("mount");
}

void cleanup_sandbox(string target) {
    if (umount((target + "/tmp").c_str())) ERREXIT("umount");
    if (umount(target.c_str())) ERREXIT("umount");
}

int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

const int COMPILE_TIME = 5000, COMPILE_MEM = 512, COMPILE_PIDS = 128,
          EXTRA_TIME = 1000;

enum verdict_t { ok, tle, mle, re, sec, uke };

struct result_t {
    verdict_t verdict;
    int time;
    ll memory;
    string stdout_content, stderr_content;
};

int child_pipe[2];

struct sandbox_input {
    int time;
    string target, stdinf;
    vector<string> cmdline;
};

int sandbox_main(void *arg) {
    sandbox_input inp = *((sandbox_input *)arg);
    auto cmdline = inp.cmdline;
    auto target = inp.target;

    if (mount("proc", (target + "/proc").c_str(), "proc", 0, nullptr))
        ERREXIT("mount");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
        ERREXIT("mount");
    if (chdir(target.c_str())) ERREXIT("chdir");
    if (pivot_root(".", ".")) ERREXIT("pivot_root");
    if (umount2(".", MNT_DETACH)) ERREXIT("umount2");
    if (chdir("/tmp")) ERREXIT("chdir");
    write_file("stdin", inp.stdinf);

    vector<char *> v(cmdline.size() + 1);
    for (int i = 0; i < (int)cmdline.size(); i++) v[i] = cmdline[i].data();
    v[cmdline.size()] = NULL;

    setuid(65534);
    setgid(65534);

    freopen("stdin", "r", stdin);
    freopen("stdout", "w", stdout);
    freopen("stderr", "w", stderr);

    close(child_pipe[1]);
    char ch;
    if (read(child_pipe[0], &ch, 1)) ERREXIT("read");
    close(child_pipe[0]);

    int pid = fork();
    if (pid < 0) ERREXIT("fork");
    if (pid) {
        for (int t = 0; t < inp.time; t += 100) {
            usleep(100000);
            int status;
            int ret = waitpid(pid, &status, WNOHANG);
            if (!ret) continue;
            if (ret == -1) ERREXIT("waitpid");
            exit((WIFEXITED(status) ? (WEXITSTATUS(status) ? 1 : 0) : 3));
        }
        exit(2);
    } else {
        char *envp[] = {nullptr};
        rlimit rl;
        rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_STACK, &rl);
        for (int fd = STDERR_FILENO + 1; fd < sysconf(_SC_OPEN_MAX); fd++)
            close(fd);
        execve(v[0], v.data(), envp);
        exit(EXIT_FAILURE);
    }
}

result_t sandbox_run(string target, string cgroup, int time, ll memory,
                     int pids, string stdinf, vector<string> cmdline) {
    cgroup += "/judge.XXXXXX";
    if (!mkdtemp(cgroup.data())) ERREXIT("mkdtemp");
    if (pipe(child_pipe) == -1) ERREXIT("pipe");
    write_file(cgroup + "/cpu.max", "100000");
    write_file(cgroup + "/memory.high", to_string(memory * 1024 * 1024));
    write_file(cgroup + "/memory.max", to_string(memory * 1024 * 1024));
    write_file(cgroup + "/memory.swap.high", to_string(memory * 1024 * 1024));
    write_file(cgroup + "/memory.swap.max", to_string(memory * 1024 * 1024));
    write_file(cgroup + "/pids.max", to_string(pids));

    const int STACK_SIZE = 1024 * 1024;
    static char stack[STACK_SIZE];
    sandbox_input inp;
    inp.target = target;
    inp.stdinf = stdinf;
    inp.cmdline = cmdline;
    inp.time = time + EXTRA_TIME;
    int child_pid = clone(
        sandbox_main, stack + STACK_SIZE,
        CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD,
        &inp);
    if (child_pid < 0) ERREXIT("clone");
    write_file(cgroup + "/cgroup.procs", to_string(child_pid));

    result_t result;
    this_thread::sleep_for(chrono::milliseconds(200));
    close(child_pipe[1]);
    int status;
    if (waitpid(child_pid, &status, 0) == -1) ERREXIT("waitpid");
    if (WIFEXITED(status)) {
        int ret = WEXITSTATUS(status);
        if (ret == 0) {
            result.verdict = verdict_t::ok;
        } else if (ret == 1) {
            result.verdict = verdict_t::re;
        } else if (ret == 2) {
            result.verdict = verdict_t::tle;
        } else if (ret == 3) {
            if (stoi(get_key(read_file(cgroup + "/memory.events"),
                             "oom_kill"))) {
                result.verdict = verdict_t::mle;
            } else {
                result.verdict = verdict_t::sec;
            }
        }
    } else {
        if (stoi(get_key(read_file(cgroup + "/memory.events"), "oom_kill"))) {
            result.verdict = verdict_t::mle;
        } else {
            result.verdict = verdict_t::uke;
        }
    }
    result.time =
        stoll(get_key(read_file(cgroup + "/cpu.stat"), "user_usec")) / 1000;
    if (result.time > time) result.verdict = verdict_t::tle;
    result.memory = stoll(read_file(cgroup + "/memory.peak")) / 1024 / 1024;
    result.stdout_content = read_file_empty(target + "/tmp/stdout");
    result.stderr_content = read_file_empty(target + "/tmp/stderr");
    rmdir(cgroup.c_str());
    // for (auto p : cmdline) cerr << p << " ";
    // cerr << endl << result.verdict << endl;
    return result;
}

vector<string> convert_cmdline(json j) {
    vector<string> v;
    for (const auto &param : j) v.push_back(param.get<string>());
    return v;
}

void copy_file(string from, string to) {
    ifstream is(from);
    ofstream os(to);
    os << is.rdbuf();
}

int root_main(void *arg) {
    char **argv = (char **)arg;
    string rootfs = argv[1], cgroup = argv[2];
    auto submission = read_json(argv[3]),
         sandbox_conf = read_json(rootfs + "/sandbox.json");
    close(uidpipe[1]);
    char ch;
    if (read(uidpipe[0], &ch, 1)) ERREXIT("read");

    json j;
    j["verdict"] = string("AC");
    j["memory"] = -1;
    j["time"] = -1;

    // We are root!
    if (sethostname("localhost", 9) == -1) ERREXIT("sethostname");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
        ERREXIT("mount");

    // create the two sandboxes
    create_sandbox(rootfs, "/tmp/run",
                   submission["problem"]["size"].get<string>());
    create_sandbox(rootfs, "/tmp/judge",
                   submission["problem"]["size"].get<string>());

    // compile solution and checker
    auto lang = submission["solution"]["language"].get<string>();
    write_file("/tmp/run/tmp/" +
                   sandbox_conf["languages"][lang]["filename"].get<string>(),
               submission["solution"]["source"].get<string>());
    if (sandbox_conf["languages"][lang].count("compile")) {
        auto res = sandbox_run(
            "/tmp/run", cgroup, COMPILE_TIME, COMPILE_MEM, COMPILE_PIDS, "",
            convert_cmdline(sandbox_conf["languages"][lang]["compile"]));
        if (res.verdict != verdict_t::ok) {
            j["verdict"] = "CE";
            j["compiler_message"] = (res.stdout_content + res.stderr_content).substr(0, 10000);
            cout << j << endl;
            return 0;
        }
    }
    auto chktype = submission["problem"]["checker"]["type"].get<string>();
    if (chktype == "testlib") {
        write_file("/tmp/judge/tmp/checker.cpp",
                   submission["problem"]["checker"]["source"].get<string>());
        auto res = sandbox_run("/tmp/judge", cgroup, COMPILE_TIME, COMPILE_MEM,
                               COMPILE_PIDS, "",
                               {"/usr/bin/g++", "checker.cpp", "-o", "checker",
                                "-lm", "-O3", "-Wall"});
        if (res.verdict != verdict_t::ok) {
            j["verdict"] = "CCE";
            j["compiler_message"] = (res.stdout_content + res.stderr_content).substr(0, 10000);
            cout << j << endl;
            return 0;
        }
    }

    int testno = 0;
    for (const auto &test : submission["problem"]["tests"]) {
        testno++;
        // run solution
        auto res = sandbox_run(
            "/tmp/run", cgroup, submission["problem"]["time"].get<int>(),
            submission["problem"]["memory"].get<ll>(), COMPILE_PIDS / 4,
            test["input"].get<string>(),
            convert_cmdline(sandbox_conf["languages"][lang]["run"]));
        if (res.time > j["time"].get<int>()) j["time"] = res.time;
        if (res.memory > j["memory"].get<ll>()) j["memory"] = res.memory;
        j["testno"] = testno;
        if (res.verdict != verdict_t::ok) {
            switch (res.verdict) {
                case verdict_t::mle:
                    j["verdict"] = "MLE";
                    break;
                case verdict_t::re:
                    j["verdict"] = "RE";
                    break;
                case verdict_t::sec:
                    j["verdict"] = "SEC";
                    break;
                case verdict_t::tle:
                    j["verdict"] = "TLE";
                    break;
                case verdict_t::uke:
                    j["verdict"] = "UKE";
                    break;
            }
            j["message"] = (res.stdout_content + res.stderr_content).substr(0, 10000);
            break;
        }

        // compare results
        write_file("/tmp/judge/tmp/input", test["input"].get<string>());
        write_file("/tmp/judge/tmp/answer", test["answer"].get<string>());
        write_file("/tmp/judge/tmp/output", res.stdout_content);

        if (chktype == "testlib") {
            auto chk_res = sandbox_run(
                "/tmp/judge", cgroup,
                submission["problem"]["time"].get<int>() * 2,
                submission["problem"]["memory"].get<ll>() * 2, COMPILE_PIDS, "",
                {"./checker", "input", "output", "answer"});
            if (chk_res.verdict != verdict_t::ok) {
                j["verdict"] = "WA";
                break;
            }
        } else {
            auto chk_res = sandbox_run(
                "/tmp/judge", cgroup,
                submission["problem"]["time"].get<int>() * 2,
                submission["problem"]["memory"].get<ll>() * 2, COMPILE_PIDS, "",
                {"/usr/bin/diff", "-Z", "output", "answer"});
            if (chk_res.verdict != verdict_t::ok) {
                j["verdict"] = "WA";
                break;
            }
        }
    }
    cout << j << endl;

    // destroy the two sandboxes
    cleanup_sandbox("/tmp/run");
    cleanup_sandbox("/tmp/judge");

    cout << j.dump();

    return 0;
}

// judger rootfs cgroup submission > results.json
int main(int argc, char **argv) {
    if (argc != 4) {
        cerr << "Usage: judger rootfs cgroup submission.json" << endl;
        exit(EXIT_FAILURE);
    }
    if (mkdir("/tmp/run", 0777) && errno != EEXIST) ERREXIT("mkdir");
    if (mkdir("/tmp/judge", 0777) && errno != EEXIST) ERREXIT("mkdir");
    if (pipe(uidpipe)) ERREXIT("pipe");
    const int STACK_SIZE = 1024 * 1024;
    static char stack[STACK_SIZE];
    int child_pid = clone(root_main, stack + STACK_SIZE,
                          CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWNET |
                              CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD,
                          argv);
    if (child_pid == -1) ERREXIT("clone");
    write_file("/proc/" + to_string(child_pid) + "/uid_map",
               "0 " + to_string(getuid()) + " 1");
    write_file("/proc/" + to_string(child_pid) + "/setgroups", "deny");
    write_file("/proc/" + to_string(child_pid) + "/gid_map",
               "0 " + to_string(getgid()) + " 1");
    close(uidpipe[1]);
    int status;
    if (waitpid(child_pid, &status, 0) == -1) ERREXIT("waitpid");
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return EXIT_FAILURE;
}
