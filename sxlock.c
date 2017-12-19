/*
 * MIT/X Consortium License
 *
 * © 2013 Jakub Klinkovský <kuba.klinkovsky at gmail dot com>
 * © 2010-2011 Ben Ruijl
 * © 2006-2008 Anselm R Garbe <garbeam at gmail dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdarg.h>     // variable arguments number
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>      // isprint()
#include <time.h>       // time()
#include <getopt.h>     // getopt_long()
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>   // mlock()
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/dpms.h>
#include <X11/extensions/Xrandr.h>
#include <security/pam_appl.h>

#ifdef __GNUC__
    #define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
    #define UNUSED(x) UNUSED_ ## x
#endif

typedef struct Dpms {
    BOOL state;
    CARD16 level;  // why?
    CARD16 standby, suspend, off;
} Dpms;

typedef struct WindowPositionInfo {
    int display_width, display_height;
    int output_x, output_y;
    int output_width, output_height;
} WindowPositionInfo;

static int conv_callback(int num_msgs, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);


/* command-line arguments */
static char* opt_font;
static char* opt_username;
static char* opt_passchar;
static Bool  opt_hidelength;

/* need globals for signal handling */
Display *dpy;
Dpms dpms_original = { .state = True, .level = 0, .standby = 600, .suspend = 600, .off = 600 };  // holds original values
int dpms_timeout = 10;  // dpms timeout until program exits
Bool using_dpms;

pam_handle_t *pam_handle;
struct pam_conv conv = { conv_callback, NULL };

/* Holds the password you enter */
static char password[256];


static void
die(const char *errstr, ...) {
    va_list ap;
    va_start(ap, errstr);
    fprintf(stderr, "%s: ", PROGNAME);
    vfprintf(stderr, errstr, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

/*
 * Clears the memory which stored the password to be a bit safer against
 * cold-boot attacks.
 *
 */
static void
clear_password_memory(void) {
    /* A volatile pointer to the password buffer to prevent the compiler from
     * optimizing this out. */
    volatile char *vpassword = password;
    for (unsigned int c = 0; c < sizeof(password); c++)
        /* rewrite with random values */
        vpassword[c] = rand();
}

/*
 * Callback function for PAM. We only react on password request callbacks.
 *
 */
static int
conv_callback(int num_msgs, const struct pam_message **msg, struct pam_response **resp, void *UNUSED(appdata_ptr)) {
    if (num_msgs == 0)
        return PAM_BUF_ERR;

    // PAM expects an array of responses, one for each message
    if ((*resp = calloc(num_msgs, sizeof(struct pam_message))) == NULL)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msgs; i++) {
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF &&
            msg[i]->msg_style != PAM_PROMPT_ECHO_ON)
            continue;

        // return code is currently not used but should be set to zero
        resp[i]->resp_retcode = 0;
        if ((resp[i]->resp = strdup(password)) == NULL) {
            free(*resp);
            return PAM_BUF_ERR;
        }
    }

    return PAM_SUCCESS;
}

void
handle_signal(int sig) {
    /* restore dpms settings */
    if (using_dpms) {
        DPMSSetTimeouts(dpy, dpms_original.standby, dpms_original.suspend, dpms_original.off);
        if (!dpms_original.state)
            DPMSDisable(dpy);
    }

    die("Caught signal %d; dying\n", sig);
}

struct TestQ {
        char *question;
        char *answer;
};

struct Test {
        size_t cur_test;
        const char *cur_question;
        const char *expected_answer;

        const char *prev_answer;
        char *wrong_answer;

        struct TestQ *tests;

        size_t s_tests;
        size_t n_tests;

        size_t n_checks;
        size_t n_correct;
        size_t n_checked;
        size_t n_were_correct;
};

static void
test_del(struct Test *test) {
        if (!test) return;
        for (size_t i = 0; i < test->n_tests; i++) {
                free(test->tests[i].answer);
                free(test->tests[i].question);
        }
        free(test->wrong_answer);
        free(test->tests);
        free(test);
}

static int
get_test_config(const char *username, char fpath[256], size_t *n_correct, size_t *n_checks) {
        char filebuf[10000];

        FILE *f = fopen("/etc/sxlock.conf", "r");
        if (!f) {
                printf("file %s not found\n", fpath);
                return 1;
        }
        for (size_t i = 0; i < sizeof filebuf; i++) {
                filebuf[i] = 0;
        }
        size_t len = fread(filebuf, sizeof filebuf, 1, f);
        if (len != len) {}
        fclose(f);
        for (size_t i = 0, f = 0; filebuf[i] != 0; i++) {
                if (filebuf[i] == '\n') {
                        char *line = filebuf + f;
                        f = i + 1;

                        char *u = strtok(line, "-");
                        if (strcmp(u, username) != 0) {
                                continue;
                        }

                        char *k = strtok(NULL, "=");
                        char *r = strtok(NULL, "\n");
                        if (!r) return 1;

                        if (strcmp(k, "path") == 0) {
                                strcpy(fpath, r);
                        } else if (strcmp(k, "checks") == 0) {
                                char *h;
                                *n_checks = strtol(r, &h, 10);
                        } else if (strcmp(k, "correct") == 0) {
                                char *h;
                                *n_correct = strtol(r, &h, 10);
                        }
                }
        }
        return 0;
}

static void
test_shuffle(struct Test *test) {
        size_t n = test->n_tests;
        struct TestQ v, *t = test->tests;

        for (size_t i = 0; i < n; i++) {
                size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
                v = t[j];
                t[j] = t[i];
                t[i] = v;
        }
}

static struct Test *
test_create(const char *username) {

        char filebuf[10000];
        size_t n_correct = 0, n_checks = 0;
        char fpath[265];

        int err = get_test_config(username, fpath, &n_correct, &n_checks);
        if (err) {
                return NULL;
        }

        // read whole file to filebuf
        for (size_t i = 0; i < sizeof filebuf; i++) {
                filebuf[i] = 0;
        }
        FILE *f = fopen(fpath, "r");
        if (!f) {
                printf("could not open file %s\n", fpath);
                return NULL;
        }
        size_t len = fread(filebuf, sizeof filebuf, 1, f);
        int had_err = ferror(f);
        fclose(f);
        if (had_err || len != len) {
                printf("had err in file %s: %s\n", fpath, strerror(had_err));
                return NULL;
        }

        // setup test from CSV file
        struct Test *t;
        t = calloc(sizeof *t, 1);

        t->s_tests = 500;
        t->tests = malloc(sizeof t->tests[0] * t->s_tests);
        size_t n = 0;
        for (size_t i = 0, f = 0; filebuf[i] != 0; i++) {
                if (filebuf[i] == ';' || filebuf[i] == '\n') {
                        char *el = malloc(i - f + 1);
                        strncpy(el, filebuf + f, i - f);
                        el[i - f] = 0;
                        f = i + 1;
                        if (n % 2 == 0) {
                                t->tests[n / 2].answer = el;
                        } else {
                                t->tests[n / 2].question = el;
                                ++t->n_tests;
                        }
                        ++n;
                }
        }

        test_shuffle(t);

        t->expected_answer = t->tests[0].answer;
        t->cur_question = t->tests[0].question;
        t->cur_test = 0;

        // check values
        t->n_checks = n_checks > 0 ? n_checks : t->n_tests;
        t->n_correct = n_correct > 0 ? n_correct : t->n_tests;

        return t;
}

static void
test_draw(struct Test *test, Window w, GC gc, WindowPositionInfo* info, unsigned int inputlen) {
        char buf[265];

        int x = info->output_x + 10;
        int y = info->output_y + 20;
        int yinc = 30;

        XClearArea(dpy, w, info->output_x, info->output_y, info->output_width / 2, info->output_height / 2 - 50, False);

        if (test->cur_question) {
                XDrawString(dpy, w, gc, x, y, test->cur_question, strlen(test->cur_question));
        }
        y += yinc;

        strncpy(buf, password, inputlen);
        buf[inputlen] = 0;
        XDrawString(dpy, w, gc, x, y, buf, strlen(buf));
        y += yinc;

        sprintf(buf, "Test %ld/%ld; Correct %ld/%ld", test->cur_test + 1, test->n_checks, test->n_were_correct, test->n_correct);
        XDrawString(dpy, w, gc, x, y, buf, strlen(buf));
        y += yinc;

        if (test->wrong_answer) {
                sprintf(buf, "%s <-> %s", test->wrong_answer, test->prev_answer);
                XDrawString(dpy, w, gc, x, y, buf, strlen(buf));
        } else if (test->prev_answer) {
                sprintf(buf, "OK: %s", test->prev_answer);
                XDrawString(dpy, w, gc, x, y, buf, strlen(buf));
        }
        y += yinc;
}

static int
test_check_answer(struct Test *test, const char *answer) {
        if (test->expected_answer == NULL) {
                return 0;
        }

        free(test->wrong_answer);
        test->wrong_answer = NULL;

        // check answer
        ++test->n_checked;
        if (strcmp(test->expected_answer, answer) != 0) {
                test->wrong_answer = strdup(answer);
        } else {
                ++test->n_were_correct;
        }
        test->prev_answer = test->expected_answer;
        ++test->cur_test;

        // get next test
        if (test->cur_test >= test->n_tests) {
                test->cur_test = 0;
        }
        test->expected_answer = test->tests[test->cur_test].answer;
        test->cur_question = test->tests[test->cur_test].question;

        // need more checks?
        int the_end = test->n_checked >= test->n_checks && test->n_were_correct >= test->n_correct;
        return !the_end;
}

void
main_loop(Window w, GC gc, XFontStruct* font, WindowPositionInfo* info, char passdisp[256], char* username, XColor UNUSED(black), XColor white, XColor red, Bool hidelength, struct Test *test) {
    XEvent event;
    KeySym ksym;

    unsigned int len = 0;
    Bool running = True;
    Bool sleepmode = False;
    Bool failed = False;

    XSync(dpy, False);

    /* define base coordinates - middle of screen */
    int base_x = info->output_x + info->output_width / 2;
    int base_y = info->output_y + info->output_height / 2;    /* y-position of the line */

    /* not changed in the loop */
    int line_x_left = base_x - info->output_width / 8;
    int line_x_right = base_x + info->output_width / 8;

    /* font properties */
    int ascent, descent;
    {
        int dir;
        XCharStruct overall;
        XTextExtents(font, passdisp, strlen(username), &dir, &ascent, &descent, &overall);
    }

    /* main event loop */
    while(running && !XNextEvent(dpy, &event)) {
        if (sleepmode && using_dpms)
            DPMSForceLevel(dpy, DPMSModeOff);

        /* update window if no events pending */
        if (!XPending(dpy)) {
            int x;
            /* draw username and line */
            x = base_x - XTextWidth(font, username, strlen(username)) / 2;
            XDrawString(dpy, w, gc, x, base_y - 10, username, strlen(username));
            XDrawLine(dpy, w, gc, line_x_left, base_y, line_x_right, base_y);

            /* clear old passdisp */
            XClearArea(dpy, w, info->output_x, base_y + 20, info->output_width, ascent + descent, False);

            /* draw new passdisp or 'auth failed' */
            if (test) {
                test_draw(test, w, gc, info, len);
            } else if (failed) {
                x = base_x - XTextWidth(font, "authentication failed", 21) / 2;
                XSetForeground(dpy, gc, red.pixel);
                XDrawString(dpy, w, gc, x, base_y + ascent + 20, "authentication failed", 21);
                XSetForeground(dpy, gc, white.pixel);
            } else {
                int lendisp = len;
                if (hidelength && len > 0)
                    lendisp += (passdisp[len] * len) % 5;
                x = base_x - XTextWidth(font, passdisp, lendisp) / 2;
                XDrawString(dpy, w, gc, x, base_y + ascent + 20, passdisp, lendisp % 256);
            }
        }

        if (event.type == MotionNotify) {
            sleepmode = False;
            failed = False;
        }

        if (event.type == KeyPress) {
            sleepmode = False;
            failed = False;

            char inputChar = 0;
            XLookupString(&event.xkey, &inputChar, sizeof(inputChar), &ksym, 0);

            switch (ksym) {
                case XK_Return:
                case XK_KP_Enter:
                    password[len] = 0;
                    if (test) {
                        running = test_check_answer(test, password);
                    } else if (pam_authenticate(pam_handle, 0) == PAM_SUCCESS) {
                        clear_password_memory();
                        running = False;
                    } else {
                        failed = True;
                    }
                    len = 0;
                    break;
                case XK_Escape:
                    len = 0;
                    sleepmode = True;
                    break;
                case XK_BackSpace:
                    if (len)
                        --len;
                    break;
                default:
                    if (isprint(inputChar) && (len + sizeof(inputChar) < sizeof password)) {
                        memcpy(password + len, &inputChar, sizeof(inputChar));
                        len += sizeof(inputChar);
                    }
                    break;
            }
        }
    }
}

Bool
parse_options(int argc, char** argv)
{
    static struct option opts[] = {
        { "font",           required_argument, 0, 'f' },
        { "help",           no_argument,       0, 'h' },
        { "passchar",       required_argument, 0, 'p' },
        { "username",       required_argument, 0, 'u' },
        { "hidelength",     no_argument,       0, 'l' },
        { "version",        no_argument,       0, 'v' },
        { 0, 0, 0, 0 },
    };

    for (;;) {
        int opt = getopt_long(argc, argv, "f:hp:u:vl", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
            case 'f':
                opt_font = optarg;
                break;
            case 'h':
                die("usage: "PROGNAME" [-hvd] [-p passchars] [-f font] [-u username]\n"
                    "   -h: show this help page and exit\n"
                    "   -v: show version info and exit\n"
                    "   -l: derange the password length indicator\n"
                    "   -p passchars: characters used to obfuscate the password\n"
                    "   -f font: X logical font description\n"
                    "   -u username: user name to show\n"
                );
                break;
            case 'p':
                opt_passchar = optarg;
                break;
            case 'u':
                opt_username = optarg;
                break;
            case 'l':
                opt_hidelength = True;
                break;
            case 'v':
                die(PROGNAME"-"VERSION", © 2013 Jakub Klinkovský\n");
                break;
            default:
                return False;
        }
    }

    return True;
}

int
main(int argc, char** argv) {
    char passdisp[256];
    int screen_num;
    WindowPositionInfo info;

    Cursor invisible;
    Window root, w;
    XColor black, red, white;
    XFontStruct* font;
    GC gc;

    /* get username (used for PAM authentication) */
    char* username;
    if ((username = getenv("USER")) == NULL)
        die("USER environment variable not set, please set it.\n");

    /* set default values for command-line arguments */
    opt_passchar = "*";
    opt_font = "-misc-fixed-medium-r-*--17-120-*-*-*-*-iso8859-1";
    opt_username = username;
    opt_hidelength = False;

    if (!parse_options(argc, argv))
        exit(EXIT_FAILURE);

    /* register signal handler function */
    if (signal (SIGINT, handle_signal) == SIG_IGN)
        signal (SIGINT, SIG_IGN);
    if (signal (SIGHUP, handle_signal) == SIG_IGN)
        signal (SIGHUP, SIG_IGN);
    if (signal (SIGTERM, handle_signal) == SIG_IGN)
        signal (SIGTERM, SIG_IGN);

    /* fill with password characters */
    for (unsigned int i = 0; i < sizeof(passdisp); i += strlen(opt_passchar))
        for (unsigned int j = 0; j < strlen(opt_passchar) && i + j < sizeof(passdisp); j++)
            passdisp[i + j] = opt_passchar[j];

    /* initialize random number generator */
    srand(time(NULL));

    if (!(dpy = XOpenDisplay(NULL)))
        die("cannot open dpy\n");

    if (!(font = XLoadQueryFont(dpy, opt_font)))
        die("error: could not find font. Try using a full description.\n");

    screen_num = DefaultScreen(dpy);
    root = DefaultRootWindow(dpy);

    /* get display/output size and position */
    {
        XRRScreenResources* screen = NULL;
        RROutput output;
        XRROutputInfo* output_info = NULL;
        XRRCrtcInfo* crtc_info = NULL;

        screen = XRRGetScreenResources (dpy, root);
        output = XRRGetOutputPrimary(dpy, root);

        /* When there is no primary output, the return value of XRRGetOutputPrimary
         * is undocumented, probably it is 0. Fall back to the first output in this
         * case, connected state will be checked later.
         */
        if (output == 0) {
            output = screen->outputs[0];
        }
        output_info = XRRGetOutputInfo(dpy, screen, output);

        /* Iterate through screen->outputs until connected output is found. */
        int i = 0;
        while (output_info->connection != RR_Connected || output_info->crtc == 0) {
            XRRFreeOutputInfo(output_info);
            output_info = XRRGetOutputInfo(dpy, screen, screen->outputs[i++]);
            fprintf(stderr, "Warning: no primary output detected, trying %s.\n", output_info->name);
            if (i == screen->noutput)
                die("error: no connected output detected.\n");
        }

        crtc_info = XRRGetCrtcInfo (dpy, screen, output_info->crtc);

        info.output_x = crtc_info->x;
        info.output_y = crtc_info->y;
        info.output_width = crtc_info->width;
        info.output_height = crtc_info->height;
        info.display_width = DisplayWidth(dpy, screen_num);
        info.display_height = DisplayHeight(dpy, screen_num);

        XRRFreeScreenResources(screen);
        XRRFreeOutputInfo(output_info);
        XRRFreeCrtcInfo(crtc_info);
    }

    /* allocate colors */
    {
        XColor dummy;
        Colormap cmap = DefaultColormap(dpy, screen_num);
        XAllocNamedColor(dpy, cmap, "orange red", &red, &dummy);
        XAllocNamedColor(dpy, cmap, "black", &black, &dummy);
        XAllocNamedColor(dpy, cmap, "white", &white, &dummy);
    }

    /* create window */
    {
        XSetWindowAttributes wa;
        wa.override_redirect = 1;
        wa.background_pixel = black.pixel;
        w = XCreateWindow(dpy, root, 0, 0, info.display_width, info.display_height,
                0, DefaultDepth(dpy, screen_num), CopyFromParent,
                DefaultVisual(dpy, screen_num), CWOverrideRedirect | CWBackPixel, &wa);
        XMapRaised(dpy, w);
    }

    /* define cursor */
    {
        char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
        Pixmap pmap = XCreateBitmapFromData(dpy, w, curs, 8, 8);
        invisible = XCreatePixmapCursor(dpy, pmap, pmap, &black, &black, 0, 0);
        XDefineCursor(dpy, w, invisible);
        XFreePixmap(dpy, pmap);
    }

    /* create Graphics Context */
    {
        XGCValues values;
        gc = XCreateGC(dpy, w, (unsigned long)0, &values);
        XSetFont(dpy, gc, font->fid);
        XSetForeground(dpy, gc, white.pixel);
    }

    /* grab pointer and keyboard */
    int len = 1000;
    while (len-- > 0) {
        if (XGrabPointer(dpy, root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
                    GrabModeAsync, GrabModeAsync, None, invisible, CurrentTime) == GrabSuccess)
            break;
        usleep(50);
    }
    while (len-- > 0) {
        if (XGrabKeyboard(dpy, root, True, GrabModeAsync, GrabModeAsync, CurrentTime) == GrabSuccess)
            break;
        usleep(50);
    }
    if (len <= 0)
        die("Cannot grab pointer/keyboard\n");

    /* set up PAM */
    {
        int ret = pam_start("sxlock", username, &conv, &pam_handle);
        if (ret != PAM_SUCCESS)
            die("PAM: %s\n", pam_strerror(pam_handle, ret));
    }

    /* Lock the area where we store the password in memory, we don’t want it to
     * be swapped to disk. Since Linux 2.6.9, this does not require any
     * privileges, just enough bytes in the RLIMIT_MEMLOCK limit. */
    if (mlock(password, sizeof(password)) != 0)
        die("Could not lock page in memory, check RLIMIT_MEMLOCK\n");

    /* handle dpms */
    using_dpms = DPMSCapable(dpy);
    if (using_dpms) {
        /* save dpms timeouts to restore on exit */
        DPMSGetTimeouts(dpy, &dpms_original.standby, &dpms_original.suspend, &dpms_original.off);
        DPMSInfo(dpy, &dpms_original.level, &dpms_original.state);

        /* set program specific dpms timeouts */
        DPMSSetTimeouts(dpy, dpms_timeout, dpms_timeout, dpms_timeout);

        /* force dpms enabled until exit */
        DPMSEnable(dpy);
    }

    struct Test *test = test_create(username);

    /* run main loop */
    main_loop(w, gc, font, &info, passdisp, opt_username, black, white, red, opt_hidelength, test);

    test_del(test);

    /* restore dpms settings */
    if (using_dpms) {
        DPMSSetTimeouts(dpy, dpms_original.standby, dpms_original.suspend, dpms_original.off);
        if (!dpms_original.state)
            DPMSDisable(dpy);
    }

    XUngrabPointer(dpy, CurrentTime);
    XFreeFont(dpy, font);
    XFreeGC(dpy, gc);
    XDestroyWindow(dpy, w);
    XCloseDisplay(dpy);
    return 0;
}
