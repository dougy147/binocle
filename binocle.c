#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

#include "./entropy.h"
#include "./signatures.h"

#define BUF_SIZE 20000

int main(int argc, char *argv[]) {
	FILE *magic = NULL; // magic file
	unsigned long int block_size = 1024;
	unsigned long int data_points = 2048;
	unsigned long int magic_size = 0;
	float trigger_low  = 0.85;
	float trigger_high = 0.95;

	char filename[500];
	strcpy(filename, argv[1]);

	magic = fopen("magic", "rb");
	magic_size = count_magic_lines(magic); // count lines in magic file
	rewind(magic);
	build_magic_bytes(magic);

	entropy_analysis(filename, block_size, data_points, trigger_high, trigger_low);
	signatures_analysis(filename, magic_size);

	return 0;
}
