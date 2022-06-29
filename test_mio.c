#include <unistd.h>
#include <fcntl.h>

int main(void)
{
    int fd = open("test_mio.c", O_RDONLY);
    if (fd < 0) return 1;
    
    char c[32] = {0};
    
    for (int i = 0; i < 32; ++i)
        c[i] = 'd';

    read(fd, c, 32);
    close(fd);
}

