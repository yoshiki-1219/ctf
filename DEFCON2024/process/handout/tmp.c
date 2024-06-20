#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

int main() {
    // 親プロセスの PID を取得
    pid_t parent_pid = getppid();

    // prepare ROPchain
    char local_data[128] = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiiijjjjjjjjkkkkkkkkllllllllmmmmmmmmnnnnnnnnoooooooopppppppp";
    struct iovec local_iov;
    local_iov.iov_base = local_data;
    local_iov.iov_len = sizeof(local_data);

    void *remote_address = 0xdeadbeef; //parent_stack_addr;
    struct iovec remote_iov;
    remote_iov.iov_base = remote_address;
    remote_iov.iov_len = sizeof(local_data);

    ssize_t bytes_written = process_vm_writev(parent_pid, &local_iov, 1, &remote_iov, 1, 0);
    return 0;
}
