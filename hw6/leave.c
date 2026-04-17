// TGDH Part 3 - Leave
// remove m_{leaving_idx}. sibling of leaving member acts as sponsor and rotates its key.
// spec convention: even idx -> sibling is idx+1, odd idx -> sibling is idx-1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

static char *load_str(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *b = malloc(sz + 1);
    size_t r = fread(b, 1, sz, f);
    b[r] = 0;
    fclose(f);
    while (r > 0 && (b[r-1] == '\n' || b[r-1] == '\r' || b[r-1] == ' ' || b[r-1] == '\t'))
        b[--r] = 0;
    return b;
}

static BIGNUM **load_secret_lines(const char *path, int *n) {
    FILE *f = fopen(path, "r");
    if (!f) { *n = 0; return NULL; }
    BIGNUM **arr = NULL;
    int cap = 0, have = 0;
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        int L = (int)strlen(line);
        while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r' || line[L-1] == ' '))
            line[--L] = 0;
        if (L == 0) continue;
        if (have == cap) {
            cap = cap ? cap * 2 : 8;
            arr = realloc(arr, cap * sizeof(BIGNUM*));
        }
        BIGNUM *bn = NULL;
        BN_hex2bn(&bn, line);
        arr[have++] = bn;
    }
    fclose(f);
    *n = have;
    return arr;
}

static char *fmt_hex256(const BIGNUM *bn) {
    char *raw = BN_bn2hex(bn);
    int L = (int)strlen(raw);
    char *out = malloc(257);
    int pad = 256 - L;
    if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) out[i] = '0';
    memcpy(out + pad, raw, L);
    out[256] = 0;
    OPENSSL_free(raw);
    return out;
}

struct tnode {
    BIGNUM *K;
    BIGNUM *BK;
    struct tnode *left;
    struct tnode *right;
    int is_leaf;
};

static struct tnode *alloc_node(int leaf) {
    struct tnode *t = calloc(1, sizeof *t);
    t->K = BN_new();
    t->BK = BN_new();
    t->is_leaf = leaf;
    return t;
}

static void wipe(struct tnode *t) {
    if (!t) return;
    wipe(t->left);
    wipe(t->right);
    BN_free(t->K);
    BN_free(t->BK);
    free(t);
}

static struct tnode *assemble(BIGNUM **s, int off, int n,
                              const BIGNUM *p, const BIGNUM *g, BN_CTX *c) {
    if (n == 1) {
        struct tnode *t = alloc_node(1);
        BN_copy(t->K, s[off]);
        BN_mod_exp(t->BK, g, t->K, p, c);
        return t;
    }
    int ln = (n + 1) / 2;
    int rn = n - ln;
    struct tnode *L = assemble(s, off, ln, p, g, c);
    struct tnode *R = assemble(s, off + ln, rn, p, g, c);
    struct tnode *P = alloc_node(0);
    P->left = L;
    P->right = R;
    /* K_parent = BK_left ^ K_right mod p */
    BN_mod_exp(P->K, L->BK, R->K, p, c);
    BN_mod_exp(P->BK, g, P->K, p, c);
    return P;
}

static void walk_leaves(struct tnode *t, struct tnode **out, int *i) {
    if (!t) return;
    if (t->is_leaf) { out[(*i)++] = t; return; }
    walk_leaves(t->left, out, i);
    walk_leaves(t->right, out, i);
}

static void walk_internals_post(struct tnode *t, struct tnode **out, int *i) {
    if (!t || t->is_leaf) return;
    walk_internals_post(t->left, out, i);
    walk_internals_post(t->right, out, i);
    out[(*i)++] = t;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "leave: need p g member_secrets leaving_idx sponsor_new_secret\n");
        return 1;
    }

    char *p_str = load_str(argv[1]);
    char *g_str = load_str(argv[2]);
    BIGNUM *p = NULL, *g = BN_new();
    BN_hex2bn(&p, p_str);
    BN_dec2bn(&g, g_str);
    BN_CTX *ctx = BN_CTX_new();

    int n;
    BIGNUM **secrets = load_secret_lines(argv[3], &n);
    if (n < 2) { fprintf(stderr, "leave: need at least 2 members to remove one\n"); return 1; }

    char *idx_s = load_str(argv[4]);
    int leaving = atoi(idx_s);
    free(idx_s);

    char *spn_s = load_str(argv[5]);
    BIGNUM *sponsor_new = NULL;
    BN_hex2bn(&sponsor_new, spn_s);

    // sibling rule from assignment spec
    int sponsor;
    if (leaving % 2 == 0) sponsor = leaving + 1;
    else                  sponsor = leaving - 1;
    if (sponsor >= n) sponsor = leaving - 1;     // safety for last-index even case

    // sponsor rotates its key
    BN_free(secrets[sponsor]);
    secrets[sponsor] = sponsor_new;

    // compact remaining members into a new list
    int new_n = n - 1;
    BIGNUM **members = calloc(new_n, sizeof(BIGNUM*));
    for (int i = 0, j = 0; i < n; i++) {
        if (i == leaving) continue;
        members[j++] = secrets[i];
    }

    struct tnode *root = assemble(members, 0, new_n, p, g, ctx);

    FILE *fp = fopen("group_key_leave.txt", "w");
    char *gk = fmt_hex256(root->K);
    fwrite(gk, 1, 256, fp); fclose(fp); free(gk);

    int total = 2 * new_n - 1;
    struct tnode **nodes = calloc(total, sizeof(struct tnode*));
    int k = 0;
    walk_leaves(root, nodes, &k);
    walk_internals_post(root, nodes, &k);

    fp = fopen("blinded_keys_leave.txt", "w");
    for (int i = 0; i < k; i++) {
        char *h = fmt_hex256(nodes[i]->BK);
        fwrite(h, 1, 256, fp); fputc('\n', fp); free(h);
    }
    fclose(fp);

    free(nodes);
    wipe(root);
    BN_free(secrets[leaving]);  // leaving member's secret wasn't added to members[]
    for (int i = 0; i < new_n; i++) BN_free(members[i]);
    free(members); free(secrets);
    BN_free(p); BN_free(g); BN_CTX_free(ctx);
    free(p_str); free(g_str); free(spn_s);
    return 0;
}
