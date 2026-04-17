#!/bin/bash
# Tree-based Group Diffie-Hellman (TGDH) Test Verification Script

TV="TGDH_TestVectors"
PASS=0
FAIL=0
TOTAL=0

check_output() {
    local desc="$1"
    local student_file="$2"
    local correct_file="$3"
    TOTAL=$((TOTAL + 1))
    if [ ! -f "$student_file" ]; then
        echo "  FAIL: $desc - output file '$student_file' not found."
        FAIL=$((FAIL + 1))
        return
    fi
    if cmp -s "$student_file" "$correct_file"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        echo "    Your output:    $(head -c 80 $student_file)..."
        echo "    Expected:       $(head -c 80 $correct_file)..."
        FAIL=$((FAIL + 1))
    fi
}

echo "  TGDH Assignment - Automated Verification"
echo ""

echo "Compiling .."

for src in setup.c join.c leave.c merge.c refresh.c; do
    out="${src%.c}"
    out="${out^}"          # capitalize first letter (bash 4+)
    log="compile_${src%.c}.log"

    gcc "$src" -lcrypto -o "$out" 2>"$log"
    if [ $? -ne 0 ]; then
        echo "FAIL: $src did not compile. See $log"
        exit 1
    fi
    echo "  $src compiled successfully."
done

echo ""

# PART 1: Tree Setup (Test Set 1)
echo "Part 1: Tree Setup (Test Set 1)"
./Setup $TV/params_p.txt $TV/params_g.txt \
    $TV/setup1_seed0.txt $TV/setup1_seed1.txt \
    $TV/setup1_seed2.txt $TV/setup1_seed3.txt \
    > setup1.log 2>&1

check_output "Setup1 group_key" "group_key_setup.txt" "$TV/correct_setup1_group_key.txt"
check_output "Setup1 blinded_keys" "blinded_keys_setup.txt" "$TV/correct_setup1_blinded_keys.txt"
echo ""

# PART 1: Tree Setup (Test Set 2)
# Note: This will overwrite test set 1 output files.
echo "Part 1: Tree Setup (Test Set 2) "
./Setup $TV/params_p.txt $TV/params_g.txt \
    $TV/setup2_seed0.txt $TV/setup2_seed1.txt \
    $TV/setup2_seed2.txt $TV/setup2_seed3.txt \
    > setup2.log 2>&1

check_output "Setup2 group_key" "group_key_setup.txt" "$TV/correct_setup2_group_key.txt"
check_output "Setup2 blinded_keys" "blinded_keys_setup.txt" "$TV/correct_setup2_blinded_keys.txt"
echo ""

# PART 2: Member Join (4 -> 5 members)
echo "Part 2: Member Join (4 -> 5 members)"
./Join $TV/params_p.txt $TV/params_g.txt \
    $TV/join1_existing_secrets.txt \
    $TV/join1_new_secret.txt \
    $TV/join1_sponsor_new_secret.txt \
    > join1.log 2>&1

check_output "Join group_key" "group_key_join.txt" "$TV/correct_join1_group_key.txt"
check_output "Join blinded_keys" "blinded_keys_join.txt" "$TV/correct_join1_blinded_keys.txt"

# Verify group key changed from setup1
if [ -f "group_key_join.txt" ]; then
    if cmp -s "group_key_join.txt" "$TV/correct_setup1_group_key.txt"; then
        echo "  FAIL: Group key did NOT change after join (should differ from setup key)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: Group key changed after join"
        PASS=$((PASS + 1))
    fi
    TOTAL=$((TOTAL + 1))
fi
echo ""

# PART 3: Member Leave (4 -> 3 members, m1 leaves)
echo "Part 3: Member Leave (m1 leaves, 4 -> 3 members)"
./Leave $TV/params_p.txt $TV/params_g.txt \
    $TV/leave1_member_secrets.txt \
    $TV/leave1_leaving_index.txt \
    $TV/leave1_sponsor_new_secret.txt \
    > leave1.log 2>&1

check_output "Leave group_key" "group_key_leave.txt" "$TV/correct_leave1_group_key.txt"
check_output "Leave blinded_keys" "blinded_keys_leave.txt" "$TV/correct_leave1_blinded_keys.txt"

# Verify group key changed from setup1
if [ -f "group_key_leave.txt" ]; then
    if cmp -s "group_key_leave.txt" "$TV/correct_setup1_group_key.txt"; then
        echo "  FAIL: Group key did NOT change after leave"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: Group key changed after leave"
        PASS=$((PASS + 1))
    fi
    TOTAL=$((TOTAL + 1))
fi
echo ""

# PART 4: Tree Merge (Group1[4] + Group2[4] = 8 members)
echo "Part 4: Tree Merge (4 + 4 = 8 members)"
./Merge $TV/params_p.txt $TV/params_g.txt \
    $TV/merge1_group1_secrets.txt \
    $TV/merge1_group2_secrets.txt \
    > merge1.log 2>&1

check_output "Merge group_key" "group_key_merge.txt" "$TV/correct_merge1_group_key.txt"
check_output "Merge blinded_keys" "blinded_keys_merge.txt" "$TV/correct_merge1_blinded_keys.txt"

# Verify merged key differs from both individual group keys
if [ -f "group_key_merge.txt" ]; then
    DIFFERS=1
    if cmp -s "group_key_merge.txt" "$TV/correct_setup1_group_key.txt"; then DIFFERS=0; fi
    if cmp -s "group_key_merge.txt" "$TV/correct_setup2_group_key.txt"; then DIFFERS=0; fi
    TOTAL=$((TOTAL + 1))
    if [ $DIFFERS -eq 1 ]; then
        echo "  PASS: Merged key differs from both individual group keys"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: Merged key matches one of the original group keys"
        FAIL=$((FAIL + 1))
    fi
fi
echo ""

# PART 5: Key Refresh (m2 updates secret in 4-member group)
echo "Part 5: Key Refresh (m2 refreshes)"
./Refresh $TV/params_p.txt $TV/params_g.txt \
    $TV/refresh1_member_secrets.txt \
    $TV/refresh1_member_index.txt \
    $TV/refresh1_new_secret.txt \
    > refresh1.log 2>&1

check_output "Refresh group_key" "group_key_refresh.txt" "$TV/correct_refresh1_group_key.txt"
check_output "Refresh blinded_keys" "blinded_keys_refresh.txt" "$TV/correct_refresh1_blinded_keys.txt"

if [ -f "group_key_refresh.txt" ]; then
    if cmp -s "group_key_refresh.txt" "$TV/correct_setup1_group_key.txt"; then
        echo "  FAIL: Group key did NOT change after refresh"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: Group key changed after refresh"
        PASS=$((PASS + 1))
    fi
    TOTAL=$((TOTAL + 1))
fi
echo ""

# summary
echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL checks)"

# Cleanup binaries and logs, uncomment them if you want to remove after tests
 rm -f Setup Join Leave Merge Refresh
 rm -f setup1.log setup2.log join1.log leave1.log merge1.log refresh1.log
 rm -f compile_setup.log compile_join.log compile_leave.log compile_merge.log compile_refresh.log

 rm -f blinded_keys_join.txt blinded_keys_leave.txt blinded_keys_merge.txt blinded_keys_refresh.txt blinded_keys_setup.txt
 rm -f group_key_join.txt group_key_leave.txt group_key_merge.txt group_key_refresh.txt group_key_setup.txt
