#include <stdio.h>
#include <stdlib.h>
//#define DEBUG
#define MEM_SIZE 0x10000

struct bignum{
    long long data;
};

typedef struct bignum bignum;
bignum *mem;

void init_buf(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void init_mem(){
    mem = malloc(sizeof(bignum)*MEM_SIZE);
}

long long toint(bignum a){
    return a.data;
}

int is_negative(bignum n){
	return toint(n)<0;
}

bignum get_bignum(){
    bignum a;
    char c;
    c = getchar();
    if (c == '%'){
        c = getchar();
        switch(c){
            case '%':
                a.data = (long long)c;
                break;
            case 'x':
                a.data = 0;
                c = getchar();
                while(c != '\n'){
                    a.data *= 16;
                    if(c >= 'A' && c <= 'F'){
                        a.data += (long long)(c - 'A' + 10);
                    }
                    else if(c >= 'a' && c <= 'f'){
                        a.data += (long long)(c - 'a' + 10);
                    }
                    else{
                        a.data += (long long)(c - '0');
                    }
                    c = getchar();
                }
                break;
            case '0' ... '9':
                a.data = (long long)(c - '0');
                c = getchar();
                while(c != '\n'){
                    a.data *= 10;
                    a.data += (long long)(c - '0');
                    c = getchar();
                }
                break;
            default:
                a.data = (long long)c;
                break;
        }
    }
    else{
        a.data = (long long)c;
    }
    // to account for the flipped input
#ifdef DEBUG
    dprintf(2, "You entered: %lld", a.data);
#endif
    a.data *= -1;
    return a;
}

bignum bignum_sub(bignum a, bignum b){
    bignum c;
    c.data = b.data - a.data;
    return c;
}


void op1(bignum a, bignum b){
    long long loc1, loc2;
    bignum op1;
    loc1 = toint(a);
    loc2 = toint(b);

#ifdef DEBUG
        dprintf(2, "\t%d -> %d\n", loc1, loc2);
#endif

    if(is_negative(a)){
        op1 = get_bignum();
    }
    else{
        op1 = mem[toint(a)];
    }

    if(is_negative(b)){
#ifdef DEBUG
        dprintf(2, "%d -> %d\n", toint(a), toint(op1));
#endif 
        
        printf("%c", toint(op1));
    }
    else{
        mem[toint(b)] = bignum_sub(op1,mem[toint(b)]);
    }
    return;
}

int op2(bignum a){
    if (toint(mem[toint(a)]) <= 0){
        return 1;
    }
    else{
        return 0;
    }
}

void read_program(char* filename){
    FILE *fp;
    fp = fopen(filename, "r");

#ifdef DEBUG
    dprintf(2, "Reading program from %s\n", filename);
#endif

    int i = 0;
    while(!feof(fp)){
        fscanf(fp, "%lld", &mem[i].data);

#ifdef DEBUG
        // printf("%d ", mem[i].data);
#endif

        i++;
    }
    fclose(fp);
}

void run_program(){
    int ip = 0;
    while(ip>=0){
#ifdef DEBUG
       dprintf(2, "%d, %d, %d", toint(mem[ip]), toint(mem[ip+1]), toint(mem[ip+2]));
       dprintf(2, "| A: %x(%d) D: %x(%d) SP: %x(%d) | ", toint(mem[3]), toint(mem[3]), toint(mem[6]), toint(mem[6]), toint(mem[7]), toint(mem[7]));
#endif
        op1(mem[ip], mem[ip+1]);
        if(op2(mem[ip+1])){
            ip = toint(mem[ip+2]);
            continue;
        }
        ip+=3;
    }
}


int main(int argc, char** argv){
	init_buf();
    init_mem();
	if(argc != 2){
		printf("usage: ./lessequalmore <file>\n");
		return 1;
	}
    read_program(argv[1]);
    run_program();
    return 0;
}
