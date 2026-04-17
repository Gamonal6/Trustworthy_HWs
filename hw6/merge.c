/*  TGDH Part 4 - Merge
    concat group1 + group2, build a fresh tree over all of them
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

static char *read_whole(const char *fn) {
    FILE *f = fopen(fn, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(sz + 1);
    size_t got = fread(b, 1, sz, f);
    b[got] = 0;
    fclose(f);
    while (got && (b[got-1]=='\n' || b[got-1]=='\r' || b[got-1]==' ' || b[got-1]=='\t'))
        b[--got] = 0;
    return b;
}

static BIGNUM **hex_lines(const char *fn, int *out_n) {
    FILE *f = fopen(fn, "r");
    if (!f) { *out_n = 0; return NULL; }
    BIGNUM **v = NULL;
    int cap = 0, cnt = 0;
    char buf[2048];
    while (fgets(buf, sizeof buf, f)) {
        int L = (int)strlen(buf);
        while (L && (buf[L-1]=='\n'||buf[L-1]=='\r'||buf[L-1]==' ')) buf[--L]=0;
        if (!L) continue;
        if (cnt == cap) { cap = cap ? cap*2 : 8; v = realloc(v, cap*sizeof(BIGNUM*)); }
        BIGNUM *x = NULL;
        BN_hex2bn(&x, buf);
        v[cnt++] = x;
    }
    fclose(f);
    *out_n = cnt;
    return v;
}

static char *pad256(const BIGNUM *bn) {
    char *r = BN_bn2hex(bn);
    int L = (int)strlen(r);
    char *o = malloc(257);
    int pad = 256 - L; if (pad < 0) pad = 0;
    memset(o, '0', pad);
    memcpy(o+pad, r, L);
    o[256] = 0;
    OPENSSL_free(r);
    return o;
}

typedef struct Tr {
    BIGNUM *K, *BK;
    struct Tr *lc, *rc;
    int leaf;
} Tr;

static Tr *node(int is_leaf) {
    Tr *t = calloc(1, sizeof *t);
    t->K = BN_new(); t->BK = BN_new();
    t->leaf = is_leaf;
    return t;
}

static void destroy(Tr *t) {
    if (!t) return;
    destroy(t->lc); destroy(t->rc);
    BN_free(t->K); BN_free(t->BK);
    free(t);
}

static Tr *make(BIGNUM **s, int off, int n, const BIGNUM *p, const BIGNUM *g, BN_CTX *ctx) {
    if (n == 1) {
        Tr *t = node(1);
        BN_copy(t->K, s[off]);
        BN_mod_exp(t->BK, g, t->K, p, ctx);
        return t;
    }
    int ln = (n + 1) / 2;
    Tr *L = make(s, off, ln, p, g, ctx);
    Tr *R = make(s, off + ln, n - ln, p, g, ctx);
    Tr *t = node(0);
    t->lc = L; t->rc = R;
    BN_mod_exp(t->K,  L->BK, R->K, p, ctx);
    BN_mod_exp(t->BK, g, t->K, p, ctx);
    return t;
}

static void pick_leaves(Tr *t, Tr **out, int *i) {
    if (!t) return;
    if (t->leaf) { out[(*i)++] = t; return; }
    pick_leaves(t->lc, out, i);
    pick_leaves(t->rc, out, i);
}
static void pick_internals(Tr *t, Tr **out, int *i) {
    if (!t || t->leaf) return;
    pick_internals(t->lc, out, i);
    pick_internals(t->rc, out, i);
    out[(*i)++] = t;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "merge: p g group1_secrets group2_secrets\n");
        return 1;
    }

    char *ph = read_whole(argv[1]);
    char *gh = read_whole(argv[2]);
    BIGNUM *p = NULL, *g = BN_new();
    BN_hex2bn(&p, ph);
    BN_dec2bn(&g, gh);
    BN_CTX *ctx = BN_CTX_new();

    int n1, n2;
    BIGNUM **g1 = hex_lines(argv[3], &n1);
    BIGNUM **g2 = hex_lines(argv[4], &n2);
    if (n1 < 1 || n2 < 1) { fprintf(stderr, "merge: empty group file\n"); return 1; }

    int N = n1 + n2;
    BIGNUM **all_members = calloc(N, sizeof(BIGNUM*));
    for (int i = 0; i < n1; i++) all_members[i]      = g1[i];
    for (int i = 0; i < n2; i++) all_members[n1 + i] = g2[i];

    Tr *root = make(all_members, 0, N, p, g, ctx);

    FILE *fp = fopen("group_key_merge.txt", "w");
    char *gk = pad256(root->K);
    fwrite(gk, 1, 256, fp); fclose(fp); free(gk);

    int total = 2 * N - 1;
    Tr **arr = calloc(total, sizeof(Tr*));
    int k = 0;
    pick_leaves(root, arr, &k);
    pick_internals(root, arr, &k);

    fp = fopen("blinded_keys_merge.txt", "w");
    for (int i = 0; i < k; i++) {
        char *h = pad256(arr[i]->BK);
        fwrite(h, 1, 256, fp); fputc('\n', fp); free(h);
    }
    fclose(fp);

    free(arr);
    destroy(root);
    for (int i = 0; i < N; i++) BN_free(all_members[i]);
    free(all_members); free(g1); free(g2);
    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    free(ph); free(gh);
    return 0;
}
