#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// for isspace
#include <ctype.h>

// for dir
#include <sys/types.h>
#include <dirent.h>


#include "cmd.h"

#define __DEBUG__

#define log_error(fmt, ...) {                    \
    printf("error: %s:%d "fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    exit(EXIT_FAILURE);}

#define log_warn(fmt, ...) {                    \
    printf("warn: %s:%d "fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__);}

#ifdef __DEBUG__
#define log_info(fmt, ...) {                    \
    printf("info: %s:%d "fmt"\r\n", __FILE__, __LINE__,  ##__VA_ARGS__);}
#else
#define log_info(fmt, ...)
#endif


#define NOTES_FILE_PATH     "/home/qigaohua/work/gitcode/stydyNotes/"
#define SAVE_DOC_INFO_FILE   NOTES_FILE_PATH"doc.info"
#define NOTES_FILE_EXTENSION ".xx"   // 笔记文件扩展名

typedef struct _title {
    char t_name[256];
    long  offset;
} title_t;

typedef struct _file {
    char f_name[256];
    title_t title[128];
    int title_num;
    // struct _file *next;
} file_t;


typedef struct {
    file_t files[128];
    unsigned int file_num;
} doc_t;


#define PROGRAM  "hzdoc"

const char *usage = "名称:\n"
                    "    "PROGRAM" - 更方便的显示笔记内容\n\n"
                    "使用:\n"
                    "    "PROGRAM" - [选项] 参数\n\n"
                    "选项:\n"
                    "    --info,   -i   显示所有笔记文件及其它们的内容标题; "
                    "-i后面加上文件名显示指定笔记文件所有的内容标题\n"
                    "    --file,   -f   指定笔记文件，后面必须加上-t选项\n"
                    "    --title,  -t   指定要显示的内容标题，前面须加上-f选项\n"
                    "    --update, -u   更新笔记内容的本地缓存文件\n";

doc_t g_doc;
// file_t *g_file;
char *cmd_file;
char *cmd_title;

char  cmd_info;
char *cmd_info_file;

char  cmd_update;
char  cmd_error;

static int doc_info_update;



int save_doc_info()
{
    FILE *fp;
    size_t wlen;

    if (g_doc.file_num == 0)
        return 0;

    fp = fopen(SAVE_DOC_INFO_FILE, "w+");
    if ( !fp )
        log_error("fopen `%s' failed.", SAVE_DOC_INFO_FILE);

    wlen = fwrite(&g_doc, sizeof g_doc, 1, fp);
    if (wlen != 1) {
        log_warn("fwrite struct g_doc to file failed");
    }
    fclose(fp);

    return 0;
}


int load_doc_info()
{
    FILE *fp;
    size_t ret = 0;

    if (access(SAVE_DOC_INFO_FILE, F_OK | R_OK))
        return 1;

    fp = fopen(SAVE_DOC_INFO_FILE, "r");
    if ( !fp )
        log_error("fopen `%s' failed.", SAVE_DOC_INFO_FILE);

    if (fread(&g_doc, sizeof g_doc, 1, fp) != 1) {
        log_warn("fread  failed: %m.");
        ret = 1;
    }

    fclose(fp);
    return ret;
}


int collect_files(const char *dirpath)
{
    DIR *dir;
    struct dirent *dt;
    size_t flen;
    file_t *file = NULL;

    dir = opendir(dirpath);
    if ( !dir )
        log_error("opendir `%s' failed: %m.", dirpath);

    while ((dt = readdir(dir)) != NULL) {
        if (dt->d_type != DT_REG)
            continue;

        flen = strlen(dt->d_name);
        if (flen <= 3) continue;
        if (strncmp(&dt->d_name[flen-3], NOTES_FILE_EXTENSION, 3))
            continue;

        // file = malloc(sizeof *file);
        // if ( !file )
        //     log_error("malloc failed: %m.");
        // memset(file, 0, sizeof *file);

        file = &g_doc.files[g_doc.file_num++];

        strncpy(file->f_name, dt->d_name, flen-3);
        file->f_name[flen-3] = '\0';

        // if ( !g_file ) {
        //     file->next = NULL;
        //     g_file = file;
        // }
        // else {
        //     file->next = g_file;
        //     g_file = file;
        // }
    }
    closedir(dir);

    return 0;
}


int collect_titles()
{
    FILE *fp;
    title_t *title;
    char newfile[512] = {0};
    char linebuf[1024] = {0};
    size_t tlen;

    file_t *file = &g_doc.files[0];
    int i = 0;

    for (; i < g_doc.file_num ; file ++, i ++) {
        snprintf(newfile, sizeof newfile, "%s"NOTES_FILE_EXTENSION, file->f_name);

        fp = fopen(newfile, "r");
        if ( !fp ) {
            log_warn("fopen `%s' failed: %m.", newfile);
            return -2;
        }

        while(fgets(linebuf, sizeof linebuf, fp)) {
            if (strncmp(linebuf, ">>>>>", 5))
                continue;
            if (fgets(linebuf, sizeof linebuf, fp)) {
                char *p = linebuf;
                while(isspace(*p)) p++;

                tlen = strlen(p);
                while(isspace(p[tlen-1])) tlen --;
                // if (p[tlen] == '\r' || p[tlen] == '\n')
                //     p[tlen] = '\0';
                p[tlen] = '\0';

                if (tlen <= 1 || tlen > 256) {
                    log_warn("file(%s) format has a error.", file->f_name);
                    continue;
                }

                // title = malloc(sizeof *title);
                // if ( !title )
                //     log_error("malloc failed: %m.");
                // memset(title, 0, sizeof *title);
                title = &file->title[file->title_num++];

                strncpy(title->t_name, p, tlen);
                title->offset = ftell(fp);
                continue;
            }
            break;
        }
        fclose(fp);
    }

    return 0;
}


int query_text(const char *file, const char *const title)
{
    FILE *fp;
    // file_t *f = g_file;
    char linebuf[1024] = {0};

    if (!file || !title) {
        log_warn("invalid param.");
        return -1;
    }

    file_t *f = &g_doc.files[0];

    for (int i = 0; i < g_doc.file_num ; f ++, i ++) {
    // for (; f; f = f->next) {
        if (strncmp(f->f_name, file, strlen(file)))
            continue;
        for (int i = 0; i < f->title_num; i ++) {
            if (strncmp(f->title[i].t_name, title, strlen(title)))
                continue;
            char newfile[512] = {0};
            snprintf(newfile, sizeof newfile, NOTES_FILE_PATH"%s"NOTES_FILE_EXTENSION, f->f_name);
            fp = fopen(newfile, "r");
            if ( !fp ) {
                log_warn("fopen `%s' failed: %m.", newfile);
                return -2;
            }
            fseek(fp, f->title[i].offset, SEEK_CUR);
            while(fgets(linebuf, sizeof newfile, fp)) {
                if (!strncmp(linebuf, "<<<<<", 5))
                    break;
                printf("\t%s", linebuf);
            }
            fclose(fp);
        }
    }

    return 0;
}


int print_doc_info(const char *filename)
{
    file_t *f = &g_doc.files[0];
    int i = 0;

    for (; i < g_doc.file_num ; f ++, i ++) {
        if ( filename ) {
            if (strncmp(f->f_name, filename, strlen(f->f_name)))
                continue;
            for(int i = 0; i < f->title_num; i ++) {
                printf("\t%s  %ld\n", f->title[i].t_name, f->title[i].offset);
            }
            break;
        }

        printf("%s: \n", f->f_name);
        for(int i = 0; i < f->title_num; i ++) {
            printf("\t%s  %ld\n", f->title[i].t_name, f->title[i].offset);
        }
    }

    return 0;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("%s", usage);
        exit(EXIT_FAILURE);
    }

    option_parse(argc, argv);
    if ( cmd_error ) {
        printf("%s", usage);
        exit(EXIT_FAILURE);
    }

    if (cmd_update || load_doc_info()) {
        collect_files(NOTES_FILE_PATH);
        collect_titles();
        doc_info_update = 1;
    }

    if ( cmd_info ) {
        print_doc_info(cmd_info_file);
    }

    if (cmd_file && cmd_title)
        query_text(cmd_file, cmd_title);

    if (doc_info_update)
        save_doc_info();

    return 0;
}
