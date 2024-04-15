import os
import tempfile
import git
import random
import string
import datetime

flag = b"cursed{7@m_IS_4_g3N1uS_41s0_c4n_tH1s_b3_C4lL3d_GCOP?_g1t_c0Mm1t_0ri3n7ed_pRogR4mm1N6}"
#flag = b"cursed{7@m_IS_4_g3N1uS}"
print(len(flag))

PREFIX_LEN = 7
LEN1 = len(flag) - 7 - 7 - 1
LEN2 = 7

def gen_chal_parameters(flag):
    # CRT generation
    part1 = flag[PREFIX_LEN:PREFIX_LEN+LEN1]
    mods = [[i%j for i in part1] for j in [2, 3, 5, 7]]

    # Matrix parameter
    key = [[1, 1, 1, 0, 0, 1, 1],
            [0, 0, 1, 0, 0, 1, 1],
            [1, 1, 1, 1, 0, 1, 0],
            [0, 1, 0, 0, 1, 1, 0],
            [1, 0, 0, 1, 0, 0, 1],
            [0, 0, 0, 1, 0, 1, 1],
            [0, 1, 1, 1, 1, 0, 1]]

    part2 = list(flag[PREFIX_LEN+LEN1:PREFIX_LEN+LEN1+LEN2])
    enc = [0]*LEN2
    for i in range(LEN2):
        for j in range(LEN2):
            enc[i] += key[i][j] * part2[j]

    print(part1, part2)
    print(enc)
    return (mods, key, enc)


def generate_empty_commit(repo, repo_dir):
    random_time1 = datetime.datetime.fromtimestamp(random.randint(0, 2147483647))
    random_time2 = datetime.datetime.fromtimestamp(random.randint(0, 2147483647))
    eye = "OoUu0Qq"
    mouth = "wvu3UVW"
    face = [i+j+i for i in eye for j in mouth]
    message = " ".join(random.choices(face, k=3))
    repo.index.commit(message,
            author_date=random_time1.strftime('%Y-%m-%d %H:%M:%S'),
            commit_date=random_time2.strftime('%Y-%m-%d %H:%M:%S'))

def modify_and_commit(repo, repo_dir, file_name, content):
    with open(repo_dir+"/"+file_name, "wb") as f:
        f.write(content)
    repo.index.add([file_name])
    generate_empty_commit(repo, repo_dir)


branch_names = {}
next_branch = {}
def create_branch_names(mods, enc):

    eye = "OoUu0Qq"
    mouth = "wvu3UVW"
    face = [i+j+i for i in eye for j in mouth]
    exists = set()
    def gen_branch_name(a):
        x = "OwO_" + "_".join(random.choices(face, k=9))
        while x in exists:
            x = "OwO_" + "_".join(random.choices(face, k=9))
        exists.add(x)
        return x


    branch_names["main"] = gen_branch_name("main")
    branch_names["fail"] = gen_branch_name("fail")

    prev = "main"
    for i, total in enumerate(enc):
        this_branch = f"sum_{i}"
        new_branch_name = gen_branch_name(this_branch)
        branch_names[this_branch] = new_branch_name
        next_branch[prev] = new_branch_name 
        prev = this_branch

    next_branch[prev] = branch_names["main"]

    prev = "main"
    for i, c  in enumerate("cursed{"):
        this_branch = f"format_{i}"
        new_branch_name = gen_branch_name(this_branch)
        branch_names[this_branch] = new_branch_name
        next_branch[prev] = new_branch_name 
        prev = this_branch

    this_branch = f"format_{len(flag)-1}"
    new_branch_name = gen_branch_name(this_branch)
    branch_names[this_branch] = new_branch_name
    next_branch[prev] = new_branch_name 
    prev = this_branch

    next_branch[prev] = branch_names["main"]

    prev="main"
    branch_chain = []
    for i, (rs, m) in enumerate(zip(mods, [2, 3, 5, 7])):
        for j, r in enumerate(rs):
            this_branch = f"crt_{i}_{j}"
            new_branch_name = gen_branch_name(this_branch)
            branch_names[this_branch] = new_branch_name
            branch_chain.append(this_branch)

    prev = "main"
    random.shuffle(branch_chain)
    for b in branch_chain:
        next_branch[prev] = branch_names[b]
        prev = b
    next_branch[prev] = branch_names["main"]

def sum_keys(key):
    to_adds = [i+PREFIX_LEN+LEN1+1 for i, k in enumerate(key) if k]
    print(to_adds)
    arr = " ".join(map(str, to_adds))
    return arr

def create_chal_repo(key0):
    tempdir = tempfile.mkdtemp(prefix="git_madness_")
    print(tempdir)
    repo = git.Repo.init(tempdir)
    os.system(f"cp git_template/* {tempdir} -r")
    repo.git.add(all=True)
    modify_and_commit(repo, tempdir, "check_flag.sh", f"""#!/bin/sh
A="${{1:-QwQ)}}"
B="${{2:-QuQ}}"
if [ $A = 'uwu' ]
then 
    git checkout {branch_names["sum_0"]} 2>/dev/null
    exec ./check_flag.sh {sum_keys(key0)}
elif [ $B = 'OwO' ]
then 
    git checkout {branch_names["crt_0_0"]} 2>/dev/null
    exec ./check_flag.sh
elif [ $A = '>w<' ]
then 
    echo 'You got the flag <^3^>'
elif [ $A = 'QuQ' ]
then 
    echo 'No flag for u ^<QwQ>^'
else
    read -p "Enter flag: " flag
    echo $flag > flag.txt
    git checkout {branch_names["format_0"]} 2>/dev/null
    exec ./check_flag.sh
fi
""".encode())
    generate_empty_commit(repo, tempdir)
    return repo, tempdir


commits_available = []
def randomize_branch_on_main(repo, branch_name):
    branch = repo.create_head(branch_names[branch_name])
    branch.commit = random.choice(commits_available)
    return branch

def add_availble_commits(repo, branch):
    global commits_available
    commits_available += repo.iter_commits(branch)


def generate_format_chain(repo, repo_dir, to_check, position):
    print(to_check, position)
    branch_ref = f"format_{position}"
    format_check = randomize_branch_on_main(repo, branch_ref)
    format_check.checkout()

    modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/sh
flag=`cat flag.txt`
char=`expr substr $flag {position+1} 1`
Char="${{char:-AAAAA}}"
if [ $Char != '{to_check}' ]
then
    git checkout {branch_names['fail']} 2>/dev/null
else
    git checkout {next_branch[branch_ref]} 2>/dev/null
    exec ./check_flag.sh uwu 5
fi
""".encode())

    add_availble_commits(repo, format_check)

def generate_crt_chain(repo, repo_dir, target, modulos, index1, index2):
    print(f"{target} mod {modulos}")
    branch_ref = f"crt_{index1}_{index2}"
    format_check = randomize_branch_on_main(repo, branch_ref)
    format_check.checkout()
    for i in range(modulos):
        if i==0:
            next_commit = branch_names[branch_ref]+"^"
        else:
            next_commit = "HEAD^"

        if (modulos-i-1)==target:
            result_branch = next_branch[branch_ref]
        else:
            result_branch = branch_names["fail"]

        modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/sh
num=`expr $1 - 1`
if [ $1 -eq 0 ]
then
    git checkout {result_branch} 2>/dev/null
    exec ./check_flag.sh '>w<'
else
    git checkout {next_commit} 2>/dev/null
    exec ./check_flag.sh $num
fi
""".encode())

    modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/sh
flag=`cat flag.txt`
char=`expr substr $flag {index2+PREFIX_LEN+1} 1`
num=`LC_CTYPE=C printf '%d' "'$char"`
git checkout HEAD^ 2>/dev/null
exec ./check_flag.sh $num
""".encode())

    add_availble_commits(repo, format_check)


def generate_sum_chain(repo, repo_dir, total, index, key):
    print(f"Sums to {total}")
    branch_ref = f"sum_{index}"
    format_check = randomize_branch_on_main(repo, branch_ref)
    format_check.checkout()
    if index < len(key) - 1:
        arr2 = sum_keys(key[index+1])
    else:
        arr2 = "HwH OwO"
    modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/sh
if [ -z $1 ]
then
    git checkout {next_branch[branch_ref]} 2>/dev/null
    exec ./check_flag.sh {arr2}
else
    git checkout {branch_names['fail']} 2>/dev/null
fi
    """.encode())

    arr = sum_keys(key[index])

    modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/bash
flag=`cat flag.txt`
char=`expr substr $flag $1 1`
alsonum=`LC_CTYPE=C printf '%d' "'$char"`
if [ -z $1 ]
then
    git checkout {branch_names['fail']} 2>/dev/null
else
    git checkout "HEAD~$alsonum" 2>/dev/null
    exec ./check_flag.sh $2 $3 $4 $5 $6 $7 $8
fi
    """.encode())
    for i in range(total-1):
        generate_empty_commit(repo, repo_dir)

    # modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#!/bin/sh
# git checkout HEAD^
# exec ./check_flag.sh {arr}
# """.encode())

    add_availble_commits(repo, format_check)

def main():
    mods, key, enc = gen_chal_parameters(flag)
    create_branch_names(mods, enc)
    print(branch_names, next_branch)
    repo, repo_dir = create_chal_repo(key[0])
    print(repo, repo_dir)
    main_branch = repo.create_head(branch_names["main"])
    main_branch.checkout()
    fail_branch = repo.create_head(branch_names["fail"])
    # make main a bit longer
    for i in range(16):
        generate_empty_commit(repo, repo_dir)

    add_availble_commits(repo, main_branch)


    fail_branch.checkout()
    modify_and_commit(repo, repo_dir, "check_flag.sh", f"""#/bin/sh
git checkout {branch_names['main']} 2>/dev/null
exec ./check_flag.sh QuQ
            """.encode())

    main_branch.checkout()
    
    for i, total in enumerate(enc):
        generate_sum_chain(repo, repo_dir, total, i, key)
        main_branch.checkout()

    for i, c  in enumerate("cursed{"):
        generate_format_chain(repo, repo_dir, c, i)
        main_branch.checkout()
    generate_format_chain(repo, repo_dir, "}", len(flag)-1)
    main_branch.checkout()

    for i, (rs, m) in enumerate(zip(mods, [2, 3, 5, 7])):
        for j, r in enumerate(rs):
            generate_crt_chain(repo, repo_dir, r, m, i, j)
            main_branch.checkout()


    os.system(f"tar -C {repo_dir} -zcvf chal.tar.gz .")

if __name__ == "__main__":
    main()

