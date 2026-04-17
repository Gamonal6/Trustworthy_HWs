/* TGDH Part 2 - Join
 * sponsor (last member) rotates its key, new member is appended,
 * tree is rebuilt with n+1 leaves
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

static char *read_trim(const char *fn) {
    FILE *f = fopen(fn, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(sz + 1);
    size_t n = fread(b, 1, sz, f); b[n] = 0; fclose(f);
    while (n && (b[n-1]=='\n'||b[n-1]=='\r'||b[n-1]==' '||b[n-1]=='\t')) b[--n]=0;
    return b;
}

static BIGNUM **read_hex_file(const char *fn, int *count) {
    FILE *f = fopen(fn, "r");
    if (!f) { *count = 0; return NULL; }
    BIGNUM **a = NULL;
    int cap = 0, c = 0;
    char buf[2048];
    while (fgets(buf, sizeof buf, f)) {
        int L = strlen(buf);
        while (L && (buf[L-1]=='\n'||buf[L-1]=='\r'||buf[L-1]==' ')) buf[--L]=0;
        if (!L) continue;
        if (c == cap) { cap = cap ? cap*2 : 8; a = realloc(a, cap * sizeof(BIGNUM*)); }
        BIGNUM *x = NULL;
        BN_hex2bn(&x, buf);
        a[c++] = x;
    }
    fclose(f);
    *count = c;
    return a;
}

static char *to_hex256(const BIGNUM *bn) {
    char *raw = BN_bn2hex(bn);
    int L = strlen(raw);
    char *out = malloc(257);
    int pad = 256 - L; if (pad < 0) pad = 0;
    memset(out, '0', pad);
    memcpy(out + pad, raw, L);
    out[256] = 0;
    OPENSSL_free(raw);
    return out;
}

typedef struct N {
    BIGNUM *K, *BK;
    struct N *l, *r;
    int is_leaf;
} N;

static N *new_n(int leaf) {
    N *x = calloc(1, sizeof *x);
    x->K = BN_new(); x->BK = BN_new();
    x->is_leaf = leaf;
    return x;
}

static void free_tree(N *x) {
    if (!x) return;
    free_tree(x->l); free_tree(x->r);
    BN_free(x->K); BN_free(x->BK);
    free(x);
}

static N *build_tree(BIGNUM **s, int off, int n, const BIGNUM *p, const BIGNUM *g, BN_CTX *ctx) {
    if (n == 1) {
        N *x = new_n(1);
        BN_copy(x->K, s[off]);
        BN_mod_exp(x->BK, g, x->K, p, ctx);
        return x;
    }
    int ln = (n + 1) / 2;
    N *L = build_tree(s, off, ln, p, g, ctx);
    N *R = build_tree(s, off + ln, n - ln, p, g, ctx);
    N *par = new_n(0);
    par->l = L; par->r = R;
    BN_mod_exp(par->K, L->BK, R->K, p, ctx);
    BN_mod_exp(par->BK, g, par->K, p, ctx);
    return par;
}

static void get_leaves(N *x, N **o, int *i) {
    if (!x) return;
    if (x->is_leaf) { o[(*i)++] = x; return; }
    get_leaves(x->l, o, i); get_leaves(x->r, o, i);
}
static void get_internals(N *x, N **o, int *i) {
    if (!x || x->is_leaf) return;
    get_internals(x->l, o, i); get_internals(x->r, o, i);
    o[(*i)++] = x;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s p g existing_secrets new_secret sponsor_new_secret\n", argv[0]);
        return 1;
    }

    char *ph = read_trim(argv[1]), *gh = read_trim(argv[2]);
    BIGNUM *p = NULL, *g = BN_new();
    BN_hex2bn(&p, ph);
    BN_dec2bn(&g, gh);
    BN_CTX *ctx = BN_CTX_new();

    int n_ex;
    BIGNUM **existing = read_hex_file(argv[3], &n_ex);
    if (!existing) { fprintf(stderr, "join: existing_secrets unreadable\n"); return 1; }

    char *new_hex = read_trim(argv[4]);
    char *spn_hex = read_trim(argv[5]);
    BIGNUM *nk = NULL, *sk = NULL;
    BN_hex2bn(&nk, new_hex);
    BN_hex2bn(&sk, spn_hex);

    /* sponsor = last existing member, replace its secret, then append the newcomer */
    BN_free(existing[n_ex - 1]);
    existing[n_ex - 1] = sk;

    int total_n = n_ex + 1;
    BIGNUM **members = calloc(total_n, sizeof(BIGNUM *));
    for (int i = 0; i < n_ex; i++) members[i] = existing[i];
    members[total_n - 1] = nk;

    N *root = build_tree(members, 0, total_n, p, g, ctx);

    char *gk = to_hex256(root->K);
    FILE *fp = fopen("group_key_join.txt", "w");
    fwrite(gk, 1, 256, fp); fclose(fp); free(gk);

    int bk_count = 2 * total_n - 1;
    N **list = calloc(bk_count, sizeof(N *));
    int idx = 0;
    get_leaves(root, list, &idx);
    get_internals(root, list, &idx);

    fp = fopen("blinded_keys_join.txt", "w");
    for (int i = 0; i < idx; i++) {
        char *h = to_hex256(list[i]->BK);
        fwrite(h, 1, 256, fp); fputc('\n', fp); free(h);
    }
    fclose(fp);

    free(list);
    free_tree(root);
    for (int i = 0; i < total_n; i++) BN_free(members[i]);
    free(members); free(existing);
    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    free(ph); free(gh); free(new_hex); free(spn_hex);
    return 0;
}
