#include <unistd.h>
#include <string.h>

int	main(void)
{
	char s[] = "ciao a tutti\n";
	write(1, s, strlen(s));
}
