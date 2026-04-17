// TGDH Part 5 - Refresh
// one member swaps its own secret and we rebuild the tree

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

static char *get_line(const char *fn) {
    FILE *f = fopen(fn, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(sz+1);
    size_t n = fread(b, 1, sz, f); b[n]=0; fclose(f);
    while (n && (b[n-1]=='\n'||b[n-1]=='\r'||b[n-1]==' ')) b[--n]=0;
    return b;
}

static BIGNUM **get_hex_list(const char *fn, int *count) {
    FILE *f = fopen(fn, "r");
    if (!f) { *count = 0; return NULL; }
    BIGNUM **out = NULL;
    int cap = 0, c = 0;
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        int L = strlen(line);
        while (L && (line[L-1]=='\n'||line[L-1]=='\r'||line[L-1]==' ')) line[--L]=0;
        if (!L) continue;
        if (c == cap) { cap = cap ? cap*2 : 8; out = realloc(out, cap*sizeof(BIGNUM*)); }
        BIGNUM *b = NULL;
        BN_hex2bn(&b, line);
        out[c++] = b;
    }
    fclose(f);
    *count = c;
    return out;
}

static char *bn_hex256(const BIGNUM *b) {
    char *r = BN_bn2hex(b);
    int L = strlen(r);
    char *o = malloc(257);
    int pad = 256 - L; if (pad < 0) pad = 0;
    memset(o, '0', pad);
    memcpy(o+pad, r, L);
    o[256] = 0;
    OPENSSL_free(r);
    return o;
}

typedef struct Nd {
    BIGNUM *K, *BK;
    struct Nd *lc, *rc;
    int is_leaf;
} Nd;

static Nd *new_nd(int leaf) {
    Nd *n = calloc(1, sizeof *n);
    n->K = BN_new();
    n->BK = BN_new();
    n->is_leaf = leaf;
    return n;
}

static void del_tree(Nd *n) {
    if (!n) return;
    del_tree(n->lc); del_tree(n->rc);
    BN_free(n->K); BN_free(n->BK);
    free(n);
}

static Nd *mk_tree(BIGNUM **s, int off, int n, const BIGNUM *p, const BIGNUM *g, BN_CTX *ctx) {
    if (n == 1) {
        Nd *x = new_nd(1);
        BN_copy(x->K, s[off]);
        BN_mod_exp(x->BK, g, x->K, p, ctx);
        return x;
    }
    int ln = (n + 1) / 2;
    Nd *L = mk_tree(s, off, ln, p, g, ctx);
    Nd *R = mk_tree(s, off + ln, n - ln, p, g, ctx);
    Nd *par = new_nd(0);
    par->lc = L; par->rc = R;
    BN_mod_exp(par->K,  L->BK, R->K, p, ctx);
    BN_mod_exp(par->BK, g, par->K, p, ctx);
    return par;
}

static void list_leaves(Nd *n, Nd **o, int *i) {
    if (!n) return;
    if (n->is_leaf) { o[(*i)++] = n; return; }
    list_leaves(n->lc, o, i);
    list_leaves(n->rc, o, i);
}
static void list_internals(Nd *n, Nd **o, int *i) {
    if (!n || n->is_leaf) return;
    list_internals(n->lc, o, i);
    list_internals(n->rc, o, i);
    o[(*i)++] = n;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "refresh: p g member_secrets refresh_idx new_secret\n");
        return 1;
    }

    char *ph = get_line(argv[1]);
    char *gh = get_line(argv[2]);
    BIGNUM *p = NULL, *g = BN_new();
    BN_hex2bn(&p, ph);
    BN_dec2bn(&g, gh);
    BN_CTX *ctx = BN_CTX_new();

    int n;
    BIGNUM **secrets = get_hex_list(argv[3], &n);
    if (n < 1) { fprintf(stderr, "refresh: no members\n"); return 1; }

    char *ix = get_line(argv[4]);
    int idx = atoi(ix);
    free(ix);

    char *nk_hex = get_line(argv[5]);
    BIGNUM *nk = NULL;
    BN_hex2bn(&nk, nk_hex);

    // swap member idx's secret
    BN_free(secrets[idx]);
    secrets[idx] = nk;

    Nd *root = mk_tree(secrets, 0, n, p, g, ctx);

    FILE *fp = fopen("group_key_refresh.txt", "w");
    char *gk = bn_hex256(root->K);
    fwrite(gk, 1, 256, fp); fclose(fp); free(gk);

    int total = 2 * n - 1;
    Nd **all = calloc(total, sizeof(Nd*));
    int k = 0;
    list_leaves(root, all, &k);
    list_internals(root, all, &k);

    fp = fopen("blinded_keys_refresh.txt", "w");
    for (int i = 0; i < k; i++) {
        char *h = bn_hex256(all[i]->BK);
        fwrite(h, 1, 256, fp); fputc('\n', fp); free(h);
    }
    fclose(fp);

    free(all);
    del_tree(root);
    for (int i = 0; i < n; i++) BN_free(secrets[i]);
    free(secrets);
    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    free(ph); free(gh); free(nk_hex);
    return 0;
}
