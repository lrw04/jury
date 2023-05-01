#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
using namespace std;
using json = nlohmann::json;

#define ERREXIT(msg)        \
    do {                    \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (false)

void write_file(std::string fn, std::string content) {
    std::ofstream st(fn);
    if (!st) ERREXIT("write");
    st << content;
    st.close();
}

std::string read_file(std::string fn) {
    std::ifstream st(fn);
    if (!st) ERREXIT("read");
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

int root_main(void *arg) {
    char **argv = (char **)arg;
    string rootfs = argv[1], cgroup = argv[2];
    auto submission = read_json(argv[3]),
         languages = read_json(rootfs + "/sandbox.json");
    close(uidpipe[1]);
    char ch;
    if (read(uidpipe[0], &ch, 1)) ERREXIT("read");

    // We are root!
    if (sethostname("sandbox", 7) == -1) ERREXIT("sethostname");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
        ERREXIT("mount");

    // create the two sandboxes

    // compile solution and checker

    for (const auto& test : submission["problem"]["tests"]) {
        // setup sandbox files

        // run solution

        // compare results
    }

    // destroy the two sandboxes

    return 0;
}

// judger rootfs cgroup submission > results.json
int main(int argc, char **argv) {
    if (argc != 4) {
        cerr << "Usage: judger rootfs cgroup submission.json" << endl;
        exit(EXIT_FAILURE);
    }
    const int STACK_SIZE = 1024 * 1024;
    if (mkdir("/tmp/run", 0777) && errno != EEXIST) ERREXIT("mkdir");
    if (mkdir("/tmp/judge", 0777) && errno != EEXIST) ERREXIT("mkdir");
    if (pipe(uidpipe)) ERREXIT("pipe");
    static char stack[STACK_SIZE];
    int child_pid = clone(root_main, stack + STACK_SIZE,
                          CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWNET |
                              CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD,
                          argv);
    if (child_pid == -1) ERREXIT("clone");
    write_file("/proc/" + to_string(child_pid) + "/uid_map",
               "0 " + to_string(getuid()) + " 1");
    write_file("/proc/" + to_string(child_pid) + "/gid_map",
               "0 " + to_string(getuid()) + " 1");
    close(uidpipe[1]);
    int status;
    if (waitpid(child_pid, &status, 0) == -1) ERREXIT("waitpid");
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return EXIT_FAILURE;
}
