#define BUF_SIZE 20000

/*
   MAGIC FILE SECTION
*/

int  max_sig_length = 0; // longest signature (to always check longest first)

// type signature_data
struct signature_data {
    int  sig_bytes[500];
    int  offset;
    char description[2000];
    int  sig_length;
} ; //signature;

// create a global array variable SIGNATURES, that will contain every signatures
struct signature_data SIGNATURES[BUF_SIZE];

int count_magic_lines(FILE* file)
{
    char buf[BUF_SIZE];
    int counter = 0;
    for(;;) {
        size_t res = fread(buf, 1, BUF_SIZE, file);
            if (ferror(file))
                    return -1;

            int i;
            for(i = 0; i < res; i++) {
            if (buf[i] =='#')
                while (buf[i++] != '\n')
                    continue;

                    if (buf[i] == '\n' && buf[i-1] != '\n' )
                counter++;
        }

            if (feof(file))
                break;
        }

    return counter - 1; // remove last empty line
}


void build_magic_bytes(FILE* file)
{
    unsigned char buf[BUF_SIZE];
    int signature_index = 0;
    bool nead_a_break_need_a_kitkat = false;

    for(;;) {
        if (nead_a_break_need_a_kitkat) {
            break;
        }
        size_t res = fread(buf, 1, BUF_SIZE, file);
            int i;
        bool new_line = true;

        struct signature_data current_signature;

            for(i = 0; i < res; i++) {
            if (i + 1 < res && buf[i+1] == EOF) { nead_a_break_need_a_kitkat = true; break; }
            if (buf[i] == '\n') { continue; }
            if (buf[i] == EOF)  { nead_a_break_need_a_kitkat = true; break; }

            // ignore comments
            while (buf[i] =='#') {
                while (buf[i] != '\n') {
                    i++;
                }
                i++;
            }

            // go until first tab
            int index = 0;
            char couple[2]; // string where to store two successive char
            int hexnumber; // store the hex number from two successive char below
            int signature_byte_index = 0;
            int length = 0;
            while (buf[i] != '\t') {
                if (buf[i] == ' ') {
                    index = 0;
                    i++;
                    continue;
                }
                couple[index] = buf[i];
                if (index == 1) {
                    sscanf(couple, "%2x", &hexnumber);
                    current_signature.sig_bytes[signature_byte_index] = (int)hexnumber;
                    signature_byte_index++;
                    index = 0;
                    i++;
                    length++;
                    continue;
                }
                index++;
                i++;
            }

            if (length == 0) {
                continue;
            }

            /*grab offset*/
            if (buf[i] == '\t') {
                i++;
                char offset_arr[500];
                int  offset_index = 0;
                int  offset;
                while (buf[i] != '\t') {
                    offset_arr[offset_index] = buf[i];
                    offset_index++;
                    i++;
                }
                sscanf(offset_arr, "%d", &offset);
                current_signature.offset = (int)offset;
            }

            /*grab description*/
            if (buf[i] == '\t') {
                i++;
                char desc_arr[500];
                int desc_index = 0;
                while (buf[i] != '\n' && buf[i] != EOF) {
                    desc_arr[desc_index] = buf[i];
                    desc_index++;
                    i++;
                }
                desc_arr[desc_index] = '\0'; // null terminate
                strcpy(current_signature.description, desc_arr);
            }

            if (signature_byte_index > max_sig_length) {
                max_sig_length = signature_byte_index;
            }
            // next signature
            SIGNATURES[signature_index] = current_signature;
            signature_index++;

            if (i + 1 < res && buf[i+1] == EOF) {
                nead_a_break_need_a_kitkat = true;
                break;
            }
        }

            if (feof(file))
                break;
        }
}

/*
   FILE SIGNATURES' CHECKING
*/

void signatures_analysis(char *filename, int number_of_signatures) {
    FILE *file = NULL;
    unsigned long int file_size;
    file = fopen(filename, "rb");

    // compute file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file != NULL) {
        int block_size = max_sig_length;
        unsigned char buffer[block_size]; // read X bytes at a time
        int remaining_size = file_size;
        size_t bytes_read = 0;
        unsigned long long int offset = 0;
        int block = 0;

        printf("\n%-15s %-15s %s\n", "DECIMAL", "HEXADECIMAL", "DESCRIPTION");
        printf("--------------------------------------------------------------------------------\n");

        while ((bytes_read = fread(buffer, 1, block_size, file)) > 0) {
            if (remaining_size < block_size) {
                block_size = remaining_size;
            }
            if (remaining_size <= 0) {
                break;
            }
            remaining_size -= block_size;
            offset = block * max_sig_length;

            // start comparing to every signatures (slow)
            int i = 0; // block cursor
            while (i < block_size) {
                bool match = false;
                int best_match_index;      // index of the matching signature
                int best_match_length = 0; // keep longest signature match (dumb)
                for (int j = 0; j < number_of_signatures; j++) {
                    // does offset match?
                    if (SIGNATURES[j].offset != offset + i) {
                        continue;
                    }
                    int sigbyte_index = 0;
                    while (sigbyte_index + i < block_size && SIGNATURES[j].sig_bytes[sigbyte_index] == buffer[sigbyte_index+i]) {
                        if (sigbyte_index > best_match_length) {
                            match = true;
                            best_match_index = j;
                            best_match_length = sigbyte_index;
                            break;
                        }
                        sigbyte_index++;
                    }
                }
                if (match == true) {
                    printf(
                        "%-15d 0x%-15X %s\n",
                        offset + i,
                        offset + i,
                        SIGNATURES[best_match_index].description
                        );
                    i+=best_match_length;
                } else {
                    i++;
                }
            }
            block++;
        }
    }
}
