#define BUF_SIZE 20000

/*
   ENTROPY SECTION
*/

float compute_entropy(unsigned char block[], int block_size) {
    float entropy = 0;
    char in_block[256] = {0};

    for (int i = 0; i < block_size; i++) {
        //printf("%d\n", block[i]);
        int dec = (unsigned char)block[i];
        in_block[dec] += 1;
    }

    for (int i = 0; i < sizeof(in_block); i ++) {
        float px = (float)in_block[i] / (float)block_size;
        if ( px > 0 ) {
            entropy -= px * log2f(px);
        }
    }

    return ( entropy / 8 );
}

void entropy_analysis(char *filename, int block_size, int data_points, float trigger_high, float trigger_low) {
    FILE *file = NULL;
    file = fopen(filename, "rb");
    // tweak block size given file (inspired from binwalk)
    unsigned long int file_size;
    unsigned char buffer[block_size];
    size_t bytes_read = 0;
    // compute file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    block_size = file_size / data_points;
    block_size = block_size + ((1024 - block_size) % 1024);
    if (block_size <= 0) {
        block_size = file_size;
    }


    if (file != NULL) {
        int last_edge = -1;
        unsigned long long int offset = 0;
        int block = 0;
        bool trigger = true;

        printf("\n%-15s %-15s %s\n", "DECIMAL", "HEXADECIMAL", "ENTROPY");
        printf("--------------------------------------------------------------------------------\n");

        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {

            offset = block * block_size;

            if (bytes_read < block_size) {
                block_size = bytes_read;
                memcpy(buffer, buffer, block_size); // just grab the number of read bytes
            }

            float entropy = compute_entropy(buffer, block_size);

            if (last_edge == 0 && entropy > trigger_low) {
                trigger = true;
            } else if (last_edge == 1 && entropy < trigger_high) {
                trigger = true;
            }

            if (trigger && entropy >= trigger_high) {
                last_edge = 1;
                trigger = false;
                printf("%-15llu 0x%-15X Rising entropy edge (%f)\n", offset, offset, entropy);
            } else if (trigger && entropy <= trigger_low) {
                last_edge = 0;
                trigger = false;
                printf("%-15llu 0x%-15X Falling entropy edge (%f)\n", offset, offset, entropy);
            }

            block++;
        }
    }
}
