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
    pdf_set_font(pdf, "Helvetica");
    pdf_append_page(pdf);
    float h = 14;
    char *t = malloc(0x450);
    char *v = malloc(0x450);
    char *w = malloc(0x450);
    //memset(t, 0x58 , 0x100);
    char *u = malloc(0x500);
    free(v);
    free(w);
    free(t);
    //memset(t, 0x56, 0x20);
    free(u);
    //printf("%s\n", *(t));
    pdf_add_text_wrap(pdf, NULL, "\x03\x56Ut ut dignissim justo, luctus finibus ipsum. Praesent posuere malesuada fermentum. Nam ligula leo, fringilla nec risus sit amet, malesuada vulputate massa. Etiam venenatis sem et erat iaculis, vitae cursus mi bibendum. Donec eget pellentesque turpis, in convallis elit. Praesent viverra velit justo, eu pretium est rhoncus eu. Suspendisse sagittis gravida lacus, laoreet posuere nisl. Etiam faucibus feugiat arcu at interdum. Duis faucibus massa eu vulputate scelerisque. Curabitur vitae leo tortor. Mauris consequat nisl ligula, sit amet tempor leo rutrum at. Fusce sit amet commodo velit. Cras varius placerat semper. Pellentesque ut imperdiet magna. Aenean at euismod ex.Nunc tincidunt quam a viverra ornare. Curabitur eget tincidunt nibh. Morbi ac egestas diam. Nullam eget cursus ex, non consequat sem. Morbi consectetur enim vel interdum posuere. Cras pellentesque ante porttitor tellus pellentesque pellentesque. Proin dui augue, ullamcorper non eleifend eget, posuere vel mi. Aliquam tempor vehicula elit, a dignissim justo aliquam id. Interdum et malesuada fames ac ante ipsum primis in faucibus. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed quis augue et ante lobortis efficitur et quis turpis.Morbi lobortis ante eget urna viverra vestibulum. Quisque dictum eros ut erat iaculis, ac bibendum dui accumsan. Sed egestas varius libero, a luctus turpis fermentum sed. Quisque convallis congue egestas. Aliquam ut venenatis metus, nec viverra metus. Nullam cursus pretium purus in laoreet. Phasellus semper auctor sodales. Duis posuere vestibulum ultrices. Suspendisse porta ultrices ante, id porta lacus bibendum eget. Nam purus augue, sollicitudin sit amet nibh ut, gravida porta nunc. ", 
                    12, 0+0x40, PDF_A4_HEIGHT-0x40, 0,  PDF_BLACK, PDF_A4_WIDTH-0x80, PDF_ALIGN_JUSTIFY, &h);

    pdf_add_text_wrap(pdf, NULL, t,
                    12, 0+0x40, PDF_A4_HEIGHT-0x40, 0,  PDF_BLACK, PDF_A4_WIDTH-0x80, PDF_ALIGN_JUSTIFY, &h);

    pdf_add_line(pdf, NULL, 50, 24, 150, 24, 3, PDF_BLACK);
    pdf_append_page(pdf);
    pdf_save(pdf, NULL);
    pdf_save(pdf, "output.pdf");
    
    struct pdf_doc *pdfe;
    
    pdf_destroy(pdf);
    //pdf_destroy(pdfe);
    return 0;
}
