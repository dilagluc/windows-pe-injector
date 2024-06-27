#include "gen.h"
#include <stdlib.h>
#include <string.h>
int main(void) {
    struct pdf_info info = {
        .creator = "My software",
        .producer = "My software",
        .title = "My document",
        .author = "My name",
        .subject = "My subject",
        .date = "Today"
    };
    struct pdf_doc *pdf = pdf_create(PDF_A4_WIDTH, PDF_A4_HEIGHT, &info);
    //pdf_set_font(pdf, "Helvetica");
    pdf_append_page(pdf);
    float h = 14;
    char *t = malloc(0x20);
    char *v = malloc(0x20);
    char *v1 = malloc(0x20);
    char *v2 = malloc(0x20);
    char *v3 = malloc(0x20);
    char *v4 = malloc(0x20);
    char *v5 = malloc(0x20);
    char *v6 = malloc(0x20);
    char *v7 = malloc(0x20);
    char *v8 = malloc(0x20);
    char *v9 = malloc(0x20);

    
    char *w = malloc(0x450);
    //memset(t, 0xbb , 0x100);
    char *u = malloc(0x100);
    free(v);
    free(v1);
    free(v2);
    free(v3);
    free(v4);
    free(v5);
    free(v6);

    //free(v7);

    free(t);
    free(v8);
    free(v9);
    //memset(t, 0xbb, 0x20);
    //free(u);
    //printf("%s\n", *(t));

    printf("%p\n", t);

    printf("%x\n", (unsigned char)t[0]);
    printf("%x\n", (unsigned char)t[1]);
    printf("%x\n", (unsigned char)t[2]);
    printf("%x\n", (unsigned char)t[3]);
    printf("%x\n", (unsigned char)t[4]);
    printf("%x\n", (unsigned char)t[5]);
    printf("%x\n", (unsigned char)t[6]);
    printf("%x\n", (unsigned char)t[7]);

    printf("eeee\n\n\n");

    //pdf_add_text_wrap(pdf, NULL, t,
    //                12, 0+0x40, PDF_A4_HEIGHT-0x40, 0,  PDF_BLACK, PDF_A4_WIDTH-0x80, PDF_ALIGN_JUSTIFY, &h);

    //pdf_add_text_wrap(pdf, NULL, "ééé £ aaa", 
    //                12, 0+0x40, PDF_A4_HEIGHT-0x40, 0,  PDF_BLACK, PDF_A4_WIDTH-0x80, PDF_ALIGN_JUSTIFY, &h);

    pdf_add_text(pdf, NULL, t, 12, 0+0x40, PDF_A4_HEIGHT-0x40, PDF_BLACK);

    //pdf_add_line(pdf, NULL, 50, 24, 150, 24, 3, PDF_BLACK);
    pdf_append_page(pdf);
    //pdf_save(pdf, NULL);
    pdf_save(pdf, "output.pdf");
    
    struct pdf_doc *pdfe;
    
    pdf_destroy(pdf);
    //pdf_destroy(pdfe);
    return 0;
}
