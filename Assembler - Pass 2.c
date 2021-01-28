#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define DEBUG 0
#define MAX_ADDR 32768
#define MAX_ADDR_STR "32768"
#define MAX_LABEL_LEN 6
#define HT_CAPACITY 100
#define WORD_LEN_BYTES 3    // SIC word = 3 bytes
#define MAX_WORD_VAL 0x00ffffff

int pass_one(FILE *input, FILE *imm);
void replace_char(char *line, char what, char to);
void get_tokens(FILE *infile, char *line, char **label, char **opcode, 
  char **operand, int line_num, char *sep);
void error_exit(FILE *infile, char *line, int line_num, char *msg);
bool is_digits(char *str);
bool valid_label(char *label);
bool valid_address(char *addr);
bool is_blank_line(char *line);
void extract_byte_str(char *line, char **byte_str);
int count_char(char *str, char ch);
int get_byte_const_len(char *str, char *line);
int find_byte_str_len(char *line);
int get_hex_str_byte_len(char *str, int len);
void init_optab();
void init_directives();
void init_symtab();

void pass_two(FILE *in, FILE *out, int prog_len);
void print_file(char *file);
void get_tokens2(FILE *immfile, char *line, char **loc_ctr, char **label, 
  char **opcode, char **operand, int line_num, char *sep);

/** things for hash table **/
/** ht collision resolution using chaining **/
struct ht_node {
  char *key;
  int value;
  struct ht_node *next;
};

typedef struct ht_node ht_node;

// 3 hash tables to use here
ht_node *SYMTAB[HT_CAPACITY];
ht_node *OPTAB[HT_CAPACITY];
ht_node *DIRECTIVES[HT_CAPACITY];

int insert(ht_node *ht[], char *key, int value);
int search(ht_node *ht[], char *key);
unsigned long hash(char *key);
void print_hashtable(ht_node *ht[]);


int main(int argc, char *argv[]) {

  char *objfileName;
  int prog_len = -1;
  char immfileName[] = "imm.txt";

  FILE *infile, *immfile, *objfile;

  if (argc != 2) {
    printf("Incorrect usage! Correct usage is:\n");
    printf("./project1 <SIC-assembly-file>\n");
    return 1;
  }

  infile = fopen(argv[1], "r");
  if (infile == NULL) {
    printf("Error in opening the file!\n");
    return -2;
  }

  init_optab();
  init_directives();
  init_symtab();

  immfile = fopen(immfileName, "w");
  prog_len = pass_one(infile, immfile);   // pass1 of assembly
  fclose(infile);                         // close files
  fclose(immfile);
  //print_hashtable(SYMTAB);       // print out symbol table (pass1 output)

  if (prog_len < 0) {
    // error in pass1
    return 0;
  }

  // pass2 now
  objfileName = (char *) malloc(sizeof(char) * (strlen(argv[1]) + 5));
  strcpy(objfileName, argv[1]);
  strcat(objfileName, ".obj");

  objfile = fopen(objfileName, "w");
  immfile = fopen(immfileName, "r");
  pass_two(immfile, objfile, prog_len);
  fclose(objfile);
  fclose(immfile);

  print_file(objfileName);
  return 0;
}

/*
directives is a hash table with values as 1 (value isn't used). 
Initialize it.
*/
void init_directives() {
  for (int i = 0; i < HT_CAPACITY; i++) 
    DIRECTIVES[i] = NULL;

  insert(DIRECTIVES, "START",  1);
  insert(DIRECTIVES, "END",  1);
  insert(DIRECTIVES, "BYTE", 1);
  insert(DIRECTIVES, "WORD", 1);
  insert(DIRECTIVES, "RESB", 1);
  insert(DIRECTIVES, "RESW", 1);
  insert(DIRECTIVES, "RESR", 1);
  insert(DIRECTIVES, "EXPORTS", 1);
}

/*
hash table of opcode to value
TODO: probably better to read from a file as this is a static table.
*/
void init_optab() {
  for (int i = 0; i < HT_CAPACITY; i++) 
    OPTAB[i] = NULL;

  insert(OPTAB, "ADD", 0x18);
  insert(OPTAB, "AND", 0x40);
  insert(OPTAB, "COMP", 0x28);
  insert(OPTAB, "DIV", 0x24);
  insert(OPTAB, "FIX", 0xC4);
  insert(OPTAB, "J", 0x3C);
  insert(OPTAB, "JEQ", 0x30);
  insert(OPTAB, "JGT", 0x34);
  insert(OPTAB, "JLT", 0x38);
  insert(OPTAB, "JSUB", 0x48);
  insert(OPTAB, "LDA", 0x00);
  insert(OPTAB, "LDB", 0x68);
  insert(OPTAB, "LDCH", 0x50);
  insert(OPTAB, "LDL", 0x08);
  insert(OPTAB, "LDX", 0x04);
  insert(OPTAB, "MUL", 0xD0);
  insert(OPTAB, "OR", 0x44);
  insert(OPTAB, "RD", 0xD8);
  insert(OPTAB, "RSUB", 0x4C);
  insert(OPTAB, "STA", 0x0C);
  insert(OPTAB, "STB", 0x78);
  insert(OPTAB, "STCH", 0x54);
  insert(OPTAB, "STL", 0x14);
  insert(OPTAB, "STX", 0x10);
  insert(OPTAB, "SUB", 0x1C);
  insert(OPTAB, "TD", 0xE0);
  insert(OPTAB, "TIX", 0x2C);
  insert(OPTAB, "WD", 0xDC);
}

/*
hash table for symbol table.
*/
void init_symtab() {
  for (int i = 0; i < HT_CAPACITY; i++) 
    SYMTAB[i] = NULL;
}

/*
Perform pass 1 of the SIC assembly and create the SYMTAB. 
It returns program_length if all good. It writes into an intermediate file
*/
int pass_one(FILE *infile, FILE *imm) {
  char *line = NULL;
  size_t len = 0;
  char *label, *opcode, *operand;
  int line_num = 0;
  int loc_ctr = 0;
  int byte_const_len = -1;
  int start_addr = 0;
  bool end_found = false;

  // loop to skip all comments
  while (getline(&line, &len, infile) != -1) {
    line_num++;

    if (is_blank_line(line)) {
      error_exit(infile, line, line_num, "Blank lines are not allowed");
    }

    if (*line != '#') {
      // breaking on first non comment line
      break;
    }
  }

  // now line is the 1st non comment line
  if (line == NULL || strlen(line) == 0) {
    printf("ERROR: source file has no code!\n");
    exit(3);
  }

  // process the 1st line
  replace_char(line, '\t', ' ');     // replace all tabs with a single space
  get_tokens(infile, line, &label, &opcode, &operand, line_num, " ");

  if (strcmp("START", opcode) != 0) {
    error_exit(infile, line, line_num, "File must start with \"START\" opcode");
  }

  if (!valid_address(operand)) {
    error_exit(infile, line, line_num, "START operand must be a valid address");
  }

  // loc_ctr is now the start address (its a hex string. Converting to int)
  loc_ctr = (int) strtol(operand, NULL, 16);

  if (loc_ctr > MAX_ADDR) {
    error_exit(infile, line, line_num, "START address must be < "MAX_ADDR_STR);
  }

  if (!valid_label(label)) {
    error_exit(infile, line, line_num, "label is invalid");
  }

  start_addr = loc_ctr;
  insert(SYMTAB, label, loc_ctr);

  if (DEBUG) {
    printf("current line: %s\n", line);
    printf("label: %s|opcode: %s|operand: %s\n", label, opcode, operand);
    printf("*************\n");
    print_hashtable(SYMTAB);
    printf("*************\n");
    printf("label: %s|opcode: %s|operand: %s\n\n", label, opcode, operand);
  }

  // write line to intermediate file as per pass1 algorithm
  fprintf(imm, "%X", loc_ctr);
  if (label != NULL)   fprintf(imm, "\t%s", label);
  if (opcode != NULL)  fprintf(imm, "\t%s", opcode);
  if (operand != NULL) fprintf(imm, "\t%s", operand);
  fprintf(imm, "%s", "\n");

  // processing the remaining lines
  while ((getline(&line, &len, infile)) != -1) {
    line_num++;
    if (is_blank_line(line)) {
      error_exit(infile, line, line_num, "Blank lines are not allowed");
    }

    replace_char(line, '\t', ' ');     // replace all tabs with a single space

    if (*line == '#') {
      // this is a comment line (starts with "#")
      fprintf(imm, "%s\n", line);
      continue;
    }

    fprintf(imm, "%X", loc_ctr);
    get_tokens(infile, line, &label, &opcode, &operand, line_num, " ");

    // there should not be any more instructions after END
    // This should never be printed as we break on finding END
    if (end_found && opcode != NULL) {
      error_exit(infile, line, line_num, "Can't have more instructions after END");
    }

    if (strcmp("END", opcode) == 0) {
      if (end_found) {
        error_exit(infile, line, line_num, "Duplicate END opcode");
      } else {
        end_found = true;
        break;  // don't read more lines
      }
    }

    if (DEBUG) {
      printf("current line: %s\n", line);
      printf("label: %s|opcode: %s|operand: %s\n", label, opcode, operand);
      printf("*************\n");
      print_hashtable(SYMTAB);
      printf("*************\n");
      printf("label: %s|opcode: %s|operand: %s\n\n", label, opcode, operand);
    }

    // now the line is not a comment. Processing further.
    if (label != NULL) {
      if (search(SYMTAB, label) >= 0) {
        error_exit(infile, line, line_num, "Duplicate label in instruction");
      } else if (valid_label(label) == false) {
        error_exit(infile, line, line_num, "label is invalid");
      } else {
        insert(SYMTAB, label, loc_ctr);
      }
    }

    if (search(OPTAB, opcode) >= 0) {
      loc_ctr += WORD_LEN_BYTES;
    } else if (strcmp("WORD", opcode) == 0) {
      if (!is_digits(operand)) {
        error_exit(infile, line, line_num, "WORD value must be digits");
      } else if ((unsigned) atoi(operand) > MAX_WORD_VAL) {
        error_exit(infile, line, line_num, "WORD value must be within 24 bits");
      } else {
        loc_ctr += WORD_LEN_BYTES;
      }
    } else if (strcmp("RESW", opcode) == 0) {

      if (!is_digits(operand)) {
        error_exit(infile, line, line_num, "RESW value must be digits");
      } else {
        loc_ctr += WORD_LEN_BYTES*atoi(operand);
      }

    } else if (strcmp("RESB", opcode) == 0) {

      if (!is_digits(operand)) {
        error_exit(infile, line, line_num, "RESB value must be digits");
      } else {
        loc_ctr += atoi(operand);
      }

    } else if (strcmp("BYTE", opcode) == 0) {
      byte_const_len = get_byte_const_len(operand, line);
      if (byte_const_len < 0) {
        error_exit(infile, line, line_num, "Invalid BYTE constant");
      } 
      loc_ctr += byte_const_len;
    } else {
      error_exit(infile, line, line_num, "Invalid operation code");
    }

    if (loc_ctr > MAX_ADDR) {
      error_exit(infile, line, line_num, "Program must fit within "MAX_ADDR_STR);
    }

    // write line to imm file
    if (label != NULL)   fprintf(imm, "\t%s", label);
    if (opcode != NULL)  fprintf(imm, "\t%s", opcode);
    if (operand != NULL) {
      if (strcmp("BYTE", opcode) == 0 && operand[0] == 'C') {
        // Ugly way to extract operand in case of BYTE. 
        // TODO: better way? This is a result of bad get_tokens(..)
        char *byte_str = (char *) malloc (sizeof(char) * (strlen(line) + 1) );
        extract_byte_str(line, &byte_str);
        fprintf(imm, "\t%s", byte_str);
      } else {
        fprintf(imm, "\t%s", operand);
      }
    }
    fprintf(imm, "%s", "\n");
  }

  if (!end_found) {
    printf("ERROR: source file has no END instruction\n");
    exit(3);
  }

  // write last line
  if (label != NULL)   fprintf(imm, "\t%s", label);
  if (opcode != NULL)  fprintf(imm, "\t%s", opcode);
  if (operand != NULL) fprintf(imm, "\t%s", operand);
  fprintf(imm, "%s", "\n");

  // if we reached here, pass1 is good. If it wasn't error_exit infile, would have
  // exited. We now return program length as loc_ctr - start_addr
  return loc_ctr - start_addr;
}


/*************Pass 2********************/

/*
Pass 2 for SIC assembler. It reads from immfile, and writes the obj code to
objfile. This is only called if there are no errors in pass1.
Imm file:
    - starts with START, 
    - ends with END, 
    - labels are correct,
    - contains comments from input
    - there are no duplicate labels, 
    - is a TSV file,
    - no blank lines etc.

Pass 2 can discover new errors (for e.g undefined label)
*/
void pass_two(FILE *immfile, FILE *objfile, int prog_len) {
  char *line = NULL;
  size_t len = 0;
  char *label, *opcode, *operand, *loc_ctr;
  int line_num = 0;
  int start_addr;
  int x_instr = 0;
  int op_len = 0;
  int oper_addr = -1;
  int opc_val = -1;
  int t = 0;
  int i = 0;
  char buf[140], buf1[5];
  int trec_addr = -1;     // 1st address in this text record
  int trec_size = 0;      // size of the current T record
  char obj_code[61];      // obj code for current record: max 60 chars
  char *str_const = NULL;
  bool is_str_const = false;

  // loop to skip all comments
  while (getline(&line, &len, immfile) != -1) {
    line_num++;
    if (*line != '#') {
      // breaking on first non comment line
      break;
    }
  }

  get_tokens2(immfile, line, &loc_ctr, &label, &opcode, &operand, line_num, "\t");
  start_addr = (int) strtol(operand, NULL, 16);

  // write H record
  fprintf(objfile, "H%-6s%06X%06X\n", label, start_addr, prog_len);

  // Initialize first Text record
  memset(obj_code, '\0', strlen(obj_code));
  trec_addr = (int) strtol(loc_ctr, NULL, 16);
  trec_size = 0;
  while ((getline(&line, &len, immfile)) != -1) {
    line_num++;

    if (*line == '#') {
      // this is a comment line - ignore
      continue;
    }

    get_tokens2(immfile, line, &loc_ctr, &label, &opcode, &operand, line_num, "\t");

    // remove \n and \r from tokens if needed
    replace_char(loc_ctr, 't', 't');
    replace_char(label, 't', 't');
    replace_char(opcode, 't', 't');
    replace_char(operand, 't', 't');

    if (strcmp("END", opcode) == 0) {
      break;  // pass 1 ensures the file ends with "END"
    }

    //printf("current line: %s", line);
    //printf("label: %s|opcode: %s|operand: %s\n", label, opcode, operand);

    // now the line is not a comment. Processing further.
    // init text record - other things come here
    x_instr = 0;
    is_str_const = false;
    opc_val = search(OPTAB, opcode);
    if (opc_val >= 0) {
      // opcode found in OPTAB
      if (operand != NULL) {
        // there is a symbol in operand field. Possibly with ",X" at the end 
        // For eg: "BUFFER", "BUFFER,X"
        op_len = strlen(operand);
        if (op_len > 2 && 
          operand[op_len-1] == 'X' &&
          operand[op_len-2] == ',') {
          // this is a symbol,X operation.
          x_instr = 1;
          strncpy(buf, operand, op_len-2);
          buf[op_len-2] = '\0';
          operand = buf;
        }

        oper_addr = search(SYMTAB, operand);
        if (oper_addr < 0) {
          error_exit(immfile, line, line_num, "PASS2: undefined symbol");
        }

      } else {
        oper_addr = 0;
      }

      // assemble obj code 
      x_instr = x_instr << 15;
      oper_addr = x_instr | oper_addr;   // set x bit
      sprintf(buf, "%02X%04X", opc_val, oper_addr);

    } else if (strcmp(opcode, "WORD") == 0) {
      // convert WORD constant to object code
      t = atoi(operand);
      sprintf(buf, "%06X", t);
      //printf("-->%s-->%s\n", operand, buf);

    } else if (strcmp(opcode, "BYTE") == 0 && operand[0] == 'X') {
      // convert BYTE constant to object code
      // E.g X'05' -> 05
      sprintf(buf, "%s", operand+2);   // +2 skips "X'"
      buf[strlen(buf) - 1] = '\0';     // kill ending quote
      //printf("-->%s-->%s\n", operand, buf);

    } else if (strcmp(opcode, "BYTE") == 0 && operand[0] == 'C') {
      // convert BYTE constant to object code
      // E.g C'EOF' -> 454F46


      is_str_const = true;
      str_const = (char *) malloc (1000);   // TODO - use malloc here?

      str_const[0] = '\0';
      for (t = 2; t < strlen(operand)-1; t++) {
        sprintf(buf1, "%2X", (int) operand[t]);
        strcat(str_const, buf1);
      }
      //printf("-->%s-->%s\n", operand, buf);
    }

    if (is_str_const) {
      // converting a string constant to obj code. Handle record spills
      // if needed.
      t = 0;
      while (t < strlen(str_const)) {

        while (t < strlen(str_const) && trec_size < 60) {
          buf1[0] = str_const[t];
          buf1[1] = str_const[t+1];
          buf1[2] = '\0';

          strcat(obj_code, buf1);  //copy 1 byte
          trec_size += 2;
          t += 2;
        }

        if (trec_size > 60) printf("This shouldn't happen. We wrote odd bytes\n"); 

        // if the record is full, write it
        if (trec_size == 60) {
          fprintf(objfile, "T%06X%02X%s\n", trec_addr, (trec_size/2), obj_code);

          // initialize 'new' Text record
          trec_size = 0;
          trec_addr += t;
          obj_code[0] = '\0';
        }
      }

      free(str_const);
    } else {

      if (trec_size + strlen(buf) > 60 ||
        strcmp(opcode, "RESB") == 0 || strcmp(opcode, "RESW") == 0) {
        // object code wont fit in current T record. So write to file
        // Incase of RESB or RESW, we need to write the current record, as 
        // there is no object code for them

        if (trec_size > 0) {
          fprintf(objfile, "T%06X%02X%s\n", trec_addr, (trec_size/2), obj_code);

          // initialize 'new' Text record
          trec_size = 0;
          trec_addr = (int) strtol(loc_ctr, NULL, 16);
          memset(obj_code, '\0', strlen(obj_code));
        }
      }

      // add object code to Text record. For RESW and RESB, 
      // there is no object code
      if (strcmp(opcode, "RESB") != 0 && strcmp(opcode, "RESW") != 0) {
        strcat(obj_code, buf);
        trec_size += strlen(buf);
      }

      //printf("==%s==\n", buf);
      //printf("==%s\n", obj_code);
    }
  }

  // write last (perhaps partially full) T record
  fprintf(objfile, "T%06X%02X%s\n", trec_addr, (trec_size/2), obj_code);

  // check if END operand is valid or not
  if (operand != NULL) {
    oper_addr = search(SYMTAB, operand);
    if (oper_addr < 0) {
      error_exit(immfile, line, line_num, "PASS2: undefined symbol");
    }
  }

  // write END record
  fprintf(objfile, "E%06X\n", oper_addr);
}

/*
Print the contents of a file to the console
*/
void print_file(char *file) {
  FILE *fp = fopen(file, "r");
  char *line = NULL;
  size_t len;

  if (fp == NULL) {
    return;
  }

  while (getline(&line, &len, fp) != -1) {
    printf("%s", line);
  }

  fclose(fp);
}


/*
Ugly function to extract BYTE operand from source line. This will be a valid
syntax line. Called only for C'...' constants

"BYTE C'hello 122 3'" -> "C'hello 122 3'"
*/
void extract_byte_str(char *line, char **byte_str) {
  int i, len;
  char *p;
  len = strlen(line);

  for (i = 0; i < len; i++) {
    // reach C'
    if (line[i] == 'C' && line[i+1] == '\'') {
      break;
    }
  }

  // copy C' to output
  p = *byte_str;
  *p = 'C';
  p++;
  *p = '\'';
  p++;
  i = i+2;

  for (; i < len; i++) {
    *p = line[i];
    if (*p == '\'') {
      // reached ending quote
      break;
    }
    p++;
  }

  p++;
  *p = '\0';
}

/*
return true if the line is blank. false otherwise
*/
bool is_blank_line(char *line) {
  bool is_blank = true;
  int i;
  char c;

  if (line != NULL) {
    for (i = 0; i < strlen(line); i++) {
      c = line[i];
      if (c != '\t' && c != ' ' && c != '\n' && c != '\r') {
        is_blank = false;
        break;
      }
    }
  }

  return is_blank;
}


/*
Return true if a given label is valid as per specs.
*/
bool valid_label(char *label) {
  if (label == NULL || strlen(label) > MAX_LABEL_LEN) {
    //printf("label is NULL or too long\n");
    return false;
  }

  if (*label < 'A' || *label > 'Z') {
    //printf("label must start with an alpha character [A-Z]\n");
    return false;
  }

  if (search(DIRECTIVES, label) >= 0) {
    //printf("label can't be a directive name\n");
    return false;
  }

  for (int i = 0; i < strlen(label); i++) {
    if (label[i] == ' ' || label[i] == '$' || label[i] == '!' 
      || label[i] == '=' || label[i] == '+' || label[i] == '-' 
      || label[i] == '(' || label[i] == ')' || label[i] == '@') {
      //printf("label contains non-allowed chars\n");
      return false;
    }
  }
  return true;
}

/*
Given a byte constant string, find and return it's length. Return -1 if
there is any error. Some examples:
X'F1'   -> 1     // 1 byte (X) 0xF1
X'F1F2' -> 2     // 2 byte (X) 0xF1F2 (note we will consider only upper case)
X'F1F'  -> -1    // 1.5 byte is invalid
XF1     -> -1    // quotes are missing
X'F1    -> -1    // quote is missing
X'FG'   -> -1    // invalid hex byte 0xFG
C'ABC'  -> 3     // 3 chars (C) 'ABC'

So..
0th char is 'X' or 'C'
1st char is single quote
last char is single quote
No single quote in between
*/
int get_byte_const_len(char *str, char *line) {
  int len = strlen(str);

  if (str[0] != 'X' && str[0] != 'C') {
    // must start with either X or C
    return -1;
  }

  if (str[0] == 'C') {
    // need to find length from C'.....' in line
    return find_byte_str_len(line);
  }

  if (str[1] != '\'' || str[len-1] != '\'') {
    // must be of the form X'...'
    return -1;
  }

  // for hex, this should be a string with hex digits and of even length
  // "X'ABCD'" -> "ABCD'", 4
  return get_hex_str_byte_len(str+2, len-3);
}

/*
This finds the byte constant str length for byte string.
SIZE BYTE C'string has space'   -> 16


Since tokens are broken on spaces, operand isn't read correctly in case of
BYTE operand containing spaces. Need to scan again.
Return -1 incase of errors
*/
int find_byte_str_len(char *line) {
  char *c;
  int len;

  if (line == NULL || count_char(line, '\'') != 2) {
    // there should be only 2 single quotes - start and end
    return -1;
  }

  c = line;
  while (*c != '\0') {
    if (*c == 'C' && *(c+1) == '\'') {
      // reached C'
      break;
    }
    c++;
  }

  c += 2;
  len = 0;
  while (*c != '\'') {
    // loop till ending ' is not found
    len++;
    c++;
  }

  return len;
}

/*
Return the no. of bytes in a hex string str. If str contains non-hex chars 
then or len is odd then return -1 (error). Lowercase hex chars are also 
invalid. For e.g.
"FFF'", 3  -> -1  (even length 3)
"A9C0K", 4 ->  2  (length is even and 1st 4 chars are hex. This is 2 bytes)
"ab01", 4  -> -1  (lowercase hex are invalid for now)
*/
int get_hex_str_byte_len(char *str, int len) {
  int i;

  if ((len % 2) == 1) {
    // odd length ain't no good
    return -1;
  }

  i = 0;
  while (i < len) {
    if (str[i] < '0') {
      return -1;
    } else if (str[i] > '9' && str[i] < 'A') {
      return -1;
    } else if (str[i] > 'F') {
      return -1;
    }
    i++;
  }

  // valid hexstr. has len/2 bytes (len will be even here)
  return len/2;
}

/*
Count and return the number of occurrences of ch in str
*/
int count_char(char *str, char ch) {
  int count = 0;
  int i = 0;
  while (i < strlen(str)) {
    if (str[i] == ch) {
      count++;
    }
    i++;
  }
  return count;
}


/*
Replace all occurrence of 'what' in line with 'to'.
If the line has \n or \r character, it is replaced with \0 to mark
the end of line
*/
void replace_char(char *str, char what, char to) {
  char *ch = str;

  if (str == NULL) {
    return;
  }

  while (*ch != '\0') {
    if (*ch == '\r' || *ch == '\n') {
      *ch = '\0';
      break;
    } else if (*ch == what) {
      *ch = to;
    }
    ch++;
  }
}

/*
check if a string contains only digits (i.e, a decimal address or number)
*/
bool is_digits(char *str) {
  if (str == NULL) {
    return false;
  }

  int i = 0;
  while (i < strlen(str)) {
    if (!isdigit(str[i])) {
      return false;
    }
    i++;
  }
  return true;
}

/*
check if the string is a valid address (i.e, contains only [0-9][A-F])
*/
bool valid_address(char *str) {
  if (str == NULL) {
    return false;
  }

  int i = 0;
  while (i < strlen(str)) {
    if (str[i] < '0') {
      return false;
    } else if (str[i] > '9' && str[i] < 'A') {
      return false;
    } else if (str[i] > 'F') {
      return false;
    }
    i++;
  }
  return true;
}

/*
Given an assembly code line, get the label, opcode and operand.
Opcode maybe null.
*/
void get_tokens(FILE *infile, char *line, char **label, 
  char **opcode, char **operand, int line_num, char *sep) {
  char *cpy = (char *) malloc( (strlen(line) + 1) * sizeof(char) );
  char *tok;
  int i;
  int max_tok = 3;      // get maximum 3 tokens [label] opcode operand
  int max_tok_len = 20; // each token is upto max_tok_len chars
  char tokens[max_tok][max_tok_len];

  strcpy(cpy, line);
  i = 0;
  tok = strtok(cpy, sep);
  strcpy(tokens[i++], tok);

  while (tok != NULL && i < max_tok) {
    tok = strtok(NULL, sep);
    if (!tok) {
      break;
    }
    strcpy(tokens[i++], tok);
  }

  if (i == 1) {
    // only opcode
    *label = NULL;

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*opcode, tokens[0]);

    *operand = NULL;
  } else if (i == 2) {

    // only opcode and operand
    *label = NULL;

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*opcode, tokens[0]);

    *operand = (char *)malloc(sizeof(char) * (strlen(tokens[1]) + 1));
    strcpy(*operand, tokens[1]);

  } else if (i == 3) {
    // line has label, opcode and operand
    *label = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*label, tokens[0]);

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[1]) + 1));
    strcpy(*opcode, tokens[1]);

    *operand = (char *)malloc(sizeof(char) * (strlen(tokens[2]) + 1));
    strcpy(*operand, tokens[2]);

  } else {
    error_exit(infile, line, line_num, "Some error in parsing line");
  }
}


/*
Get tokes from the intermediate file. This part is really ugly:
we could do better tokenize?
*/
void get_tokens2(FILE *immfile, char *line, char **loc_ctr, char **label, 
  char **opcode, char **operand, int line_num, char *sep) {
  char *cpy = (char *) malloc( (strlen(line) + 1) * sizeof(char) );
  char *tok;
  int i;
  int max_tok = 4;       // get maximum 4 tokens loc_ctr [label] opcode operand
  int max_tok_len = 100; // each token is upto max_tok_len chars
  char tokens[max_tok][max_tok_len];

  strcpy(cpy, line);
  i = 0;
  tok = strtok(cpy, sep);
  strcpy(tokens[i++], tok);

  while (tok != NULL && i < max_tok) {
    tok = strtok(NULL, sep);
    if (!tok) {
      break;
    }
    strcpy(tokens[i++], tok);
  }

  if (i == 2) {
    // only opcode
    *loc_ctr = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*loc_ctr, tokens[0]);

    *label = NULL;

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[1]) + 1));
    strcpy(*opcode, tokens[1]);

    *operand = NULL;

  } else if (i == 3) {
    *loc_ctr = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*loc_ctr, tokens[0]);

    // only opcode and operand
    *label = NULL;

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[1]) + 1));
    strcpy(*opcode, tokens[1]);

    *operand = (char *)malloc(sizeof(char) * (strlen(tokens[2]) + 1));
    strcpy(*operand, tokens[2]);

  } else if (i == 4) {
    // line has label, opcode and operand
    *loc_ctr = (char *)malloc(sizeof(char) * (strlen(tokens[0]) + 1));
    strcpy(*loc_ctr, tokens[0]);

    *label = (char *)malloc(sizeof(char) * (strlen(tokens[1]) + 1));
    strcpy(*label, tokens[1]);

    *opcode = (char *)malloc(sizeof(char) * (strlen(tokens[2]) + 1));
    strcpy(*opcode, tokens[2]);

    *operand = (char *)malloc(sizeof(char) * (strlen(tokens[3]) + 1));
    strcpy(*operand, tokens[3]);

  } else {
    error_exit(immfile, line, line_num, "Pass2: error in parsing line");
  }
}

/*
print assembly error message and exit
*/
void error_exit(FILE *infile, char *line, int line_num, char *msg) {
  printf("ASSEMBLY ERROR:\n");
  printf("%s\n", line);
  printf("Line %d: %s\n", line_num, msg);
  if (infile != NULL) {
    fclose(infile);
  }
  exit(3);
}


/*** following is hash table related code ***/

/* insert a given key into the hash table. Collision resolution by 
chaining.
It returns the index of the chain where this got inserted
*/
int insert(ht_node *ht[], char *key, int value) {
  ht_node *x;
  unsigned long i;

  x = (ht_node *) malloc(sizeof(ht_node));
  i = hash(key) % HT_CAPACITY;

  x->key = (char *) malloc((strlen(key) + 1)*sizeof(char));
  strcpy(x->key, key);

  x->value = value;
  x->next = ht[i];
  ht[i] = x;     // inserting x at the beginning of list in ht[i]

  return i;
}

/*
Search for a given key in the hash table. Return the value if found.
-1 in case of not found (note: all values in ht are positive, so -1 can
indicate error)
*/
int search(ht_node *ht[], char *key) {
  int i = hash(key) % HT_CAPACITY;
  ht_node *t = ht[i];

  while (t) {
    if (strcmp(t->key, key) == 0) {
      return t->value;
    }
    t = t->next;
  }

  return -1;
}

/* compute and return the hash of a string 
*/
unsigned long hash(char *str) {
  unsigned long hash = 5381;
  int i = 0;
  while ( i<strlen(str) )
  {
    char c = str[i];
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    i++;
  }
  return hash;
}

/*
Print the contents of the hash table
*/
void print_hashtable(ht_node *ht[]) {
  for (int i = 0; i < HT_CAPACITY; i++) {
    ht_node *t = ht[i];
    while (t) {
      printf("%s\t%X\n", t->key, t->value);
      t = t->next;
    }
  }
}