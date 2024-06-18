#include "server.h"
#include <sys/types.h>
#include <unistd.h>
#include <locale.h>
#include <stdlib.h>

int
main(int argc, char *argv[]) {
	struct timeval tv;
	struct server *s;

	/* The setlocale() function is used to set or query the program's current locale.
     * 
     * The function is used to set the current locale of the program and the 
     * collation of the specified locale. Specifically, the LC_COLLATE parameter
     * represents the collation of the region. By setting it to an empty string,
     * the default locale collation is used.*/
    setlocale(LC_COLLATE, "");

	/* The  tzset()  function initializes the tzname variable from the TZ environment variable.  
     * This function is automati‐cally called by the other time conversion functions 
     * that depend on the timezone.*/
    tzset();
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);

	if(argc > 1) {
		s = server_new(argv[1]);
	} else {
		s = server_new("webdis.json");
	}

	server_start(s);

	return EXIT_SUCCESS;
}

