#include <stdio.h>

int main(){
    int s = 0;
    scanf("%d", &s);

    if(s == 2){
        printf("%d, success\n", s);
    }
    printf("%d, fail\n", s);
    
    return 0;
}