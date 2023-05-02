#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <reproc++/run.hpp>
using namespace std;
using json = nlohmann::json;

json read_json(string fn) {
    ifstream st(fn);
    json j;
    st >> j;
    return j;
}

void copy_file(string from, string to) {
    ifstream is(from);
    ofstream os(to);
    os << is.rdbuf();
}

// builder sandbox.json output
int main(int argc, char **argv) {
    if (argc != 3) {
        cerr << "Usage: builder sandbox.json output" << endl;
        return EXIT_FAILURE;
    }
    auto sandbox_config = read_json(argv[1]);
    string output = argv[2], url = sandbox_config["base"].get<string>();
    if (mkdir(argv[2], 0666) && errno != EEXIST) {
        cerr << "Error creating output directory" << endl;
        return EXIT_FAILURE;
    }
    umask(0);
    int status;
    error_code ec;
    vector<const char *> cmdline_dl{"curl", "-L", "-o", "rootfs.tar.gz", url.c_str(),
                                    nullptr};
    tie(status, ec) = reproc::run(cmdline_dl.data());
    if (ec || status) {
        cerr << "Download failed" << endl;
        return EXIT_FAILURE;
    }
    cmdline_dl[4] = "https://github.com/MikeMirzayanov/testlib/raw/0.9.12/testlib.h";
    cmdline_dl[3] = "testlib.h";
    tie(status, ec) = reproc::run(cmdline_dl.data());
    if(ec || status) {
        cerr << "testlib.h download failed" << endl;
        return EXIT_FAILURE;
    }
    vector<const char *> cmdline_extract{
        "tar", "-x", "-f", "rootfs.tar.gz", "-C", output.c_str(), nullptr};
    tie(status, ec) = reproc::run(cmdline_extract.data());
    if (ec || status) {
        cerr << "Extraction failed" << endl;
        return EXIT_FAILURE;
    }
    copy_file("testlib.h", output + "/usr/include/testlib.h");
    unlink("rootfs.tar.gz");
    unlink("testlib.h");
    copy_file("/etc/resolv.conf", output + "/etc/resolv.conf");
    copy_file(argv[1], output + "/sandbox.json");
    chroot(argv[2]);
    chdir("/");
    for (const auto &[lang, prop] : sandbox_config["languages"].items()) {
        cerr << "Installing " << lang << endl;
        for (const auto &cmd : prop["install"]) {
            system(cmd.get<string>().c_str());
        }
    }
}