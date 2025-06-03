---
title: "Git Immersion: A Deep Dive into Version Control"
summary: "Introducing Git: the version control system that makes coding feel like a walk in the park... with occasional rain."
description: "Basics of Git, the version control system that makes coding feel like a walk in the park... with occasional rain."
categories: ["Version Control"]
tags:  ["Git", "Version Control", "Development"]
date: 2025-06-03
draft: false
---
# Lab 1
I've already installed `ruby` and set up my git global config.
```console
user.name=D3LET3-57
user.email=xxxxxxxxxxxxxxxxx@gmail.com
core.autocrlf=input
core.safecrlf=true
```
# Lab 2
No commands were run in this lab.

# Lab 3
```console
mkdir hello
cd hello
echo 'puts "Hello, World"' > hello.rb
cat hello.rb
git init
git add hello.rb
git commit -m "First Commit"
```
I've created a new directory called `hello`, added a Ruby script that prints "Hello, World", and committed it to a new git repository.
# Lab 4
```bash
➜  hello git:(master) git status                  
On branch master
nothing to commit, working tree clean
```
Status shows that there are no changes to commit, and the working tree is clean.
# Lab 5
```bash
➜  hello git:(master) echo 'puts "Hello, #{ARGV.first}!"' > hello.rb

➜  hello git:(master) ✗ cat hello.rb
puts "Hello, #{ARGV.first}!"
➜  hello git:(master) ✗ git status
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   hello.rb

no changes added to commit (use "git add" and/or "git commit -a")
```
I've modified the `hello.rb` file to accept an argument and print "Hello, {argument}!". The `git status` command shows that the file has been modified but not staged for commit.
# Lab 6
```bash
➜  hello git:(master) ✗ git add hello.rb
➜  hello git:(master) ✗ git status      
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.rb
```
I've staged the changes made to `hello.rb`. The `git status` command now shows that the file is ready to be committed.
# Lab 7
Explained about staging and committing changes in Git. Staging allows you to prepare changes before committing them to the repository. The `git add` command stages changes, while `git commit` saves those changes to the repository with a message describing the changes.
# Lab 8
```bash
➜  hello git:(master) ✗ git commit                  
[master 0136159] Using ARGV
 1 file changed, 1 insertion(+), 1 deletion(-)
➜  hello git:(master) git status
On branch master
nothing to commit, working tree clean
```
Ive got Nano as default editor, so I had to use `git commit` without the `-m` flag to write a commit message. The commit was successful, and the working tree is clean.
# Lab 9
```bash
➜  hello git:(master) echo 'name = ARGV.first || "World"' > hello.rb
➜  hello git:(master) ✗ echo 'puts "Hello, #{name}!"' >> hello.rb

➜  hello git:(master) ✗ cat hello.rb 
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(master) ✗ git add hello.rb   
➜  hello git:(master) ✗ vim hello.rb  
➜  hello git:(master) ✗ cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(master) ✗ git status      
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.rb

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   hello.rb

➜  hello git:(master) ✗ git commit -m "Added a default value"
[master 0a4623a] Added a default value
 1 file changed, 2 insertions(+), 1 deletion(-)
➜  hello git:(master) ✗ git status
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   hello.rb

no changes added to commit (use "git add" and/or "git commit -a")
➜  hello git:(master) ✗ git add .
➜  hello git:(master) ✗ git status
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.rb

➜  hello git:(master) ✗ git commit -m "Added a comment"
[master 5f9df6a] Added a comment
 1 file changed, 1 insertion(+)
```
Notice how `hello.rb` is listed twice in the status. The first change (adding a default) is staged and is ready to be committed. The second change (adding a comment) is unstaged. If you were to commit right now, the comment would not be saved in the repository.

# Lab 10
```bash
git log
git log --pretty=oneline
git log --pretty=oneline --max-count=2
git log --pretty=oneline --since='5 minutes ago'
git log --pretty=oneline --until='5 minutes ago'
git log --pretty=oneline --author=<your name>
git log --pretty=oneline --all
git log --all --pretty=format:'%h %cd %s (%an)' --since='7 days ago'
git log --all --pretty=format:'%h %cd %s (%an)' --since='7 days ago' --author=<your name>
git log --pretty=format:'%h %ad | %s%d [%an]' --graph --date=short
```
The `--pretty="..."` option customizes how each commit is displayed in the log output. Here are some common placeholders used in the format string:

- `%h`: Abbreviated commit hash
- `%d`: Decorations (e.g., branch names, tags)
- `%ad`: Author date (format can be customized with `--date=...`)
- `%s`: Commit message (subject)
- `%an`: Author name

The `--graph` flag adds an ASCII graph showing the branch and merge history, making it easier to visualize the commit tree. Using `--date=short` displays dates in a concise `YYYY-MM-DD` format.

# Lab 11
Added first set of aliases to `~/.gitconfig`:
```ini
[alias]
  co = checkout
  ci = commit
  st = status
  br = branch
  hist = log --pretty=format:'%h %ad | %s%d [%an]' --graph --date=short
  type = cat-file -t
  dump = cat-file -p
```
Second set of aliases to `.zshrc`:
```ini
alias gst='git status '
alias ga='git add '
alias gb='git branch '
alias gc='git commit'
alias gd='git diff'
alias gco='git checkout '
alias gk='gitk --all&'
alias gx='gitx --all'
```

# Lab 12
```bash
➜  hello git:(main) git hist           
➜  hello git:(main) gco 0a4623a
Note: switching to '0a4623a'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 0a4623a Added a default value
➜  hello git:(0a4623a) cat hello.rb
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(0a4623a) gco main   
Previous HEAD position was 0a4623a Added a default value
Switched to branch 'main'
➜  hello git:(main) cat hello.rb 
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
```
I used the `git hist` alias to view the commit history, then checked out a specific commit using `gco 0a4623a`. After viewing the file at that commit, I switched back to the `main` branch using `gco main`.
# Lab 13
```bash
➜  hello git:(main) git tag v1
➜  hello git:(main) gco v1^   
Note: switching to 'v1^'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 0a4623a Added a default value
➜  hello git:(0a4623a) cat hello.rb
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(0a4623a) git tag v1-beta
➜  hello git:(v1-beta) gco v1         
Previous HEAD position was 0a4623a Added a default value
HEAD is now at 5f9df6a Added a comment
➜  hello git:(v1) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(v1) gco v1-beta 
Previous HEAD position was 5f9df6a Added a comment
HEAD is now at 0a4623a Added a default value
➜  hello git:(v1-beta) cat hello.rb
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(v1-beta) git hist -a    
➜  hello git:(v1-beta) gco v1     
Previous HEAD position was 0a4623a Added a default value
HEAD is now at 5f9df6a Added a comment
➜  hello git:(v1) git hist -a
```
I created a tag `v1` at the commit `0a4623a`, then checked out the commit before the tag using `gco v1^`. I made a new tag `v1-beta` at that commit. After checking out the `v1` tag, I verified that the file content was as expected. Finally, I used `git hist -a` to view the commit history with all branches and tags.

# Lab 14
```bash
➜  hello git:(v1) gco main
Switched to branch 'main'
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) vim hello.rb
➜  hello git:(main) ✗ gst     
On branch main
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   hello.rb

no changes added to commit (use "git add" and/or "git commit -a")
➜  hello git:(main) ✗ gco hello.rb
Updated 1 path from the index
➜  hello git:(main) gst         
On branch main
nothing to commit, working tree clean
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
```
I switched to the `main` branch, modified `hello.rb`, and then used `gco hello.rb` to restore the file to its last committed state. The `git status` command confirmed that there were no changes left in the working tree, and the file content was restored to its previous state.

# Lab 15
```bash
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) vim hello.rb
➜  hello git:(main) ✗ ga hello.rb               
➜  hello git:(main) ✗ gst        
On branch main
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.rb

➜  hello git:(main) ✗ cat hello.rb
# This is an unwanted but staged comment
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) ✗ gco hello.rb
Updated 0 paths from the index
➜  hello git:(main) ✗ cat hello.rb
# This is an unwanted but staged comment
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) ✗ git reset HEAD hello.rb
Unstaged changes after reset:
M       hello.rb
➜  hello git:(main) ✗ gco hello.rb           
Updated 1 path from the index
➜  hello git:(main) gst         
On branch main
nothing to commit, working tree clean
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
```
I staged a change in `hello.rb` that I didn't want to keep, then used `git reset HEAD hello.rb` to unstage it. After that, I restored the file to its last committed state using `gco hello.rb`, which reverted the unwanted change. The `git status` command confirmed that there were no changes left in the working tree, and the file content was restored to its previous state.

# Lab 16
```bash
➜  hello git:(main) vim hello.rb
➜  hello git:(main) ✗ cat hello.rb
# This is an unwanted but committed comment
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) ✗ ga hello.rb               
➜  hello git:(main) ✗ gc -m "Oops, we didn't want this commit"
[main db8e267] Oops, we didn't want this commit
 1 file changed, 1 insertion(+), 1 deletion(-)
➜  hello git:(main) cat hello.rb                            
# This is an unwanted but committed comment
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) git revert HEAD                         
[main c4d7a0a] Revert "Oops, we didn't want this commit"
 1 file changed, 1 insertion(+), 1 deletion(-)
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) git hist -a 
```
I made an unwanted commit to `hello.rb`, then used `git revert HEAD` to create a new commit that undoes the changes made in the last commit. The file content was restored to its previous state, and the `git hist -a` command confirmed the new revert commit in the history.

# Lab 17
```bash
➜  hello git:(main) git hist           
➜  hello git:(main) git tag oops              
➜  hello git:(main) git reset --hard v1    
HEAD is now at 5f9df6a Added a comment
➜  hello git:(main) git hist           
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
```
I created a tag `oops` at the current commit, then used `git reset --hard v1` to reset the repository to the state of the `v1` tag. This command discarded all changes made after the `v1` tag, including the unwanted commit. The file content was restored to its state at the `v1` tag, and the `git hist` command confirmed that the history was reset accordingly.
Resets on local branches are generally safe. Any “accidents” can usually be recovered from by just resetting again with the desired commit.

However, if the branch is shared on remote repositories, resetting can confuse other users sharing the branch.
# Lab 18
```bash
hello git:(main) git tag -d oops    
Deleted tag 'oops' (was c4d7a0a)
➜  hello git:(main) git hist -a            
```
The oops tag is no longer listed in the repository.

# Lab 19
```bash
➜  hello git:(main) cat hello.rb
# Default is "World"
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) vim hello.rb
➜  hello git:(main) ✗ cat hello.rb
# Default is "World"
# Author: D3LET3
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) ✗ git add hello.rb
➜  hello git:(main) ✗ git commit -m "Add an author comment"
[main a69a526] Add an author comment
 1 file changed, 1 insertion(+)
➜  hello git:(main) cat hello.rb                         
# Default is "World"
# Author: D3LET3
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) vim hello.rb
➜  hello git:(main) ✗ cat hello.rb
# Default is "World"
# Author: D3LET3
# Email: REDACTED
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) ✗ git add hello.rb                     
➜  hello git:(main) ✗ git commit --amend -m "Add an author/email comment"
[main 85af29c] Add an author/email comment
 Date: Tue Jun 3 16:29:38 2025 +0530
 1 file changed, 2 insertions(+)
➜  hello git:(main) git hist -a    
```
I added an author comment to `hello.rb`, committed it, then amended the commit to include an email address. The `git hist -a` command confirmed the updated commit history with the new author and email comments.
# Lab 20
```bash
➜  hello git:(main) mkdir lib     
➜  hello git:(main) git mv hello.rb lib 
➜  hello git:(main) ✗ git status 
On branch main
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        renamed:    hello.rb -> lib/hello.rb

➜  hello git:(main) ✗ git commit -m "Moved hello.rb to lib"
[main 20e3e36] Moved hello.rb to lib
 1 file changed, 0 insertions(+), 0 deletions(-)
 rename hello.rb => lib/hello.rb (100%)
➜  hello git:(main) ls
lib
```
I moved `hello.rb` to a new directory called `lib` using `git mv`, then committed the change. The `git status` command confirmed that the file was renamed and staged for commit, and the commit history was updated accordingly.
# Lab 21
```bash
➜  hello git:(main) vim Rakefile                         
➜  hello git:(main) ✗ cat Rakefile 
#!/usr/bin/ruby -wKU

task :default => :run

task :run do
  require './lib/hello'
end

➜  hello git:(main) ✗ git add Rakefile
➜  hello git:(main) ✗ gc -m "Added a Rakefile"                
[main 4dbc382] Added a Rakefile
 1 file changed, 8 insertions(+)
 create mode 100644 Rakefile
➜  hello git:(main) rake       
Hello, World!
```
I created a `Rakefile` that defines a default task to run the `hello.rb` script located in the `lib` directory. After adding and committing the `Rakefile`, I ran `rake`, which executed the task and printed "Hello, World!" to the console.
# Lab 22
```bash
➜  hello git:(main) ls -C .git 
branches  COMMIT_EDITMSG  config  description  HEAD  hooks  index  info  logs  objects  ORIG_HEAD  packed-refs  refs
➜  hello git:(main) ls -C .git/objects 
01  0a  11  16  20  27  29  40  47  4d  50  59  5a  5f  6f  71  7c  84  85  8c  a6  af  c4  c5  db  ed  f2  info  pack
➜  hello git:(main) ls -C .git/objects/01 
3615927a2efd63ddea466b0952e481c6f73bc4
➜  hello git:(main) cat .git/config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
➜  hello git:(main) ls .git/refs
heads  tags
➜  hello git:(main) ls .git/refs/heads
main
➜  hello git:(main) ls .git/refs/tags
v1  v1-beta
➜  hello git:(main) ls .git/refs/tags/v1
.git/refs/tags/v1
➜  hello git:(main) cat .git/refs/tags/v1        
5f9df6a02d6ccc4ad98703cf84ea0e47b5aec2ff
➜  hello git:(main) cat .git/HEAD 
ref: refs/heads/main
```
I explored the `.git` directory structure, which contains various files and directories that Git uses to manage the repository. Key components include:
- `.git/objects`: Stores all the objects (blobs, trees, commits) that make up the repository.
- `.git/refs`: Contains references to commits, including branches and tags.
- `.git/config`: The configuration file for the repository, which includes settings like file mode and bare repository status.
- `.git/HEAD`: Points to the current branch or commit, indicating the state of the working directory.
# Lab 23
```bash
➜  hello git:(main) git hist --max-count=1
➜  hello git:(main) git cat-file -t  4dbc382
commit
➜  hello git:(main) git cat-file -p  4dbc382
tree 5a96ab208ab1b85cc72fcfd0ec7e7331be37a12e
parent 20e3e36cf348faa3f398431ad4da63d397407098
author D3LET3-57 <REDACTED> 1748949031 +0530
committer D3LET3-57 <REDACTED> 1748949031 +0530

Added a Rakefile
➜  hello git:(main) git cat-file -p 5a96ab208ab1b85cc72fcfd0ec7e7331be37a12e        
100644 blob f21f041d8674f589298d160e0a1b55e01a3d4247    Rakefile
040000 tree 6f7e18702e74ce163490b473b4f4441d852c4791    lib
➜  hello git:(main) git cat-file -p 6f7e18702e74ce163490b473b4f4441d852c4791                                        
100644 blob 50fe9e8e7452eab5f47145f9e0f54d74f803e423    hello.rb
➜  hello git:(main) git cat-file -p 50fe9e8e7452eab5f47145f9e0f54d74f803e423                                        
# Default is "World"
# Author: D3LET3
# Email: REDACTED
name = ARGV.first || "World"
puts "Hello, #{name}!"
```
I used `git cat-file` to inspect the commit object `4dbc382`, which shows the tree structure and parent commit. The tree object `5a96ab208ab1b85cc72fcfd0ec7e7331be37a12e` contains the files in the commit, including the `Rakefile` and the `hello.rb` file in the `lib` directory. The content of `hello.rb` is displayed, confirming the changes made in the commit.
# Lab 24
```bash
➜  hello git:(main) gco -b greet            
Switched to a new branch 'greet'
➜  hello git:(greet) 
➜  hello git:(greet) git status  
On branch greet
nothing to commit, working tree clean
➜  hello git:(greet) ls
lib  Rakefile
➜  hello git:(greet) vim lib/greeter.rb
➜  hello git:(greet) ✗ ga lib/greeter.rb 
➜  hello git:(greet) ✗ gc -m "Added a greeter class"
[greet 047fc2b] Added a greeter class
 1 file changed, 8 insertions(+)
 create mode 100644 lib/greeter.rb
➜  hello git:(greet) vim lib/hello.rb 
➜  hello git:(greet) ✗ ga lib/hello.rb              
➜  hello git:(greet) ✗ gc -m "Hello uses Greeter"   

[greet e64c2f8] Hello uses Greeter
 1 file changed, 6 insertions(+), 4 deletions(-)
➜  hello git:(greet) ✗ 
➜  hello git:(greet) vim Rakefile    
➜  hello git:(greet) ✗ ga Rakefile               
➜  hello git:(greet) ✗ gc -m "Updated Rakefile"  
[greet cb4831a] Updated Rakefile
 1 file changed, 1 insertion(+), 2 deletions(-)
 ```
 I created a new branch `greet`, added a `greeter.rb` class, modified `hello.rb` to use the `Greeter` class, and updated the `Rakefile` accordingly. Each change was staged and committed with appropriate messages. The `git status` command confirmed that there were no changes left to commit in the working tree.

# Lab 25
```bash
➜  hello git:(greet) gco main                
Switched to branch 'main'
➜  hello git:(main) cat lib/hello.rb 
# Default is "World"
# Author: D3LET3
# Email: REDACTED
name = ARGV.first || "World"
puts "Hello, #{name}!"
➜  hello git:(main) gco greet 
Switched to branch 'greet'
➜  hello git:(greet) cat lib/hello.rb
require 'greeter'

# Default is World
name = ARGV.first || "World"

greeter = Greeter.new(name)
puts greeter.greet
```
I switched back to the `main` branch to view the original `hello.rb` file, then switched to the `greet` branch to see the modified version that uses the `Greeter` class. The content of `hello.rb` in the `greet` branch reflects the changes made in that branch.
# Lab 26
```bash
➜  hello git:(greet) gco main 
Switched to branch 'main'
➜  hello git:(main) vim README.md
➜  hello git:(main) ✗ cat README.md   
This is the Hello World example from the git tutorial.

➜  hello git:(main) ✗ git add README
fatal: pathspec 'README' did not match any files
➜  hello git:(main) ✗ git add README.md 
➜  hello git:(main) ✗ git commit -m "Added README"
[main 895a1b8] Added README
 1 file changed, 2 insertions(+)
 create mode 100644 README.md
```
I added a `README.md` file to the `main` branch with a brief description of the project. The file was staged and committed successfully, and the commit history was updated accordingly.
# Lab 27
```bash
 hello git:(main) git hist -a   
* 895a1b8 2025-06-03 | Added README (HEAD -> main) [D3LET3-57]
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
I used `git hist -a` to view the commit history, which now includes the new `README.md` file and all previous commits. The output shows the commit hashes, dates, messages, and authors for each commit, providing a complete overview of the project's history.
# Lab 28
```bash
 hello git:(main) gco greet  
Switched to branch 'greet'
➜  hello git:(greet) type gm  
gm is an alias for git merge
➜  hello git:(greet) gm main  
Merge made by the 'ort' strategy.
 README.md | 2 ++
 1 file changed, 2 insertions(+)
 create mode 100644 README.md
*   58c0382 2025-06-03 | Merge branch 'main' into greet (HEAD -> greet) [D3LET3-57]
|\  
| * 895a1b8 2025-06-03 | Added README (main) [D3LET3-57]
* | cb4831a 2025-06-03 | Updated Rakefile [D3LET3-57]
* | e64c2f8 2025-06-03 | Hello uses Greeter [D3LET3-57]
* | 047fc2b 2025-06-03 | Added a greeter class [D3LET3-57]
|/  
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
I merged the `main` branch into the `greet` branch using the `gm` alias for `git merge`. The merge was successful, and the `README.md` file was added to the `greet` branch. The commit history now reflects the merge, showing the combined changes from both branches.

# Lab 29
```bash
➜  hello git:(greet) gco main 
Switched to branch 'main'
➜  hello git:(main) vim lib/hello.rb
➜  hello git:(main) ✗ git add lib/hello.rb
➜  hello git:(main) ✗ git commit -m "Made interactive"
[main 1277033] Made interactive
 1 file changed, 4 insertions(+), 5 deletions(-)
➜  hello git:(main) git hist --all
* 1277033 2025-06-03 | Made interactive (HEAD -> main) [D3LET3-57]
| *   58c0382 2025-06-03 | Merge branch 'main' into greet (greet) [D3LET3-57]
| |\  
| |/  
|/|   
* | 895a1b8 2025-06-03 | Added README [D3LET3-57]
| * cb4831a 2025-06-03 | Updated Rakefile [D3LET3-57]
| * e64c2f8 2025-06-03 | Hello uses Greeter [D3LET3-57]
| * 047fc2b 2025-06-03 | Added a greeter class [D3LET3-57]
|/  
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
I modified `lib/hello.rb` to make it interactive, allowing the user to input their name. After staging and committing the changes, I used `git hist --all` to view the complete commit history across all branches. The output shows the latest commit on the `main` branch and the merge commit from the `greet` branch, along with all previous commits.
# Lab 30
```bash
➜  hello git:(main) gco greet     
Switched to branch 'greet'
➜  hello git:(greet) gm main  
Auto-merging lib/hello.rb
CONFLICT (content): Merge conflict in lib/hello.rb
Automatic merge failed; fix conflicts and then commit the result.
➜  hello git:(greet) ✗ cat lib/hello.rb
<<<<<<< HEAD
require 'greeter'

# Default is World
name = ARGV.first || "World"

greeter = Greeter.new(name)
puts greeter.greet
=======
puts "What's your name"
my_name = gets.strip

puts "Hello, #{my_name}!"
>>>>>>> main
➜  hello git:(greet) ✗ vim lib/hello.rb
➜  hello git:(greet) ✗ git add lib/hello.rb
➜  hello git:(greet) ✗ git commit -m "Merged main fixed conflict."
[greet 7913c56] Merged main fixed conflict.
➜  hello git:(greet) 
```
I attempted to merge the `main` branch into the `greet` branch, which resulted in a merge conflict in `lib/hello.rb`. I resolved the conflict by editing the file to combine both changes, then staged and committed the resolved file. The commit history was updated to reflect the merge resolution.
# Lab 31
Let’s explore the differences between merging and rebasing. In order to do so, we need to rewind the repository back in time before the first merge, and then redo the same steps, but using rebasing rather than merging.

We will make use the of the reset command to wind the branches back in time.

# Lab 32
```bash
➜  hello git:(greet) gco greet
Already on 'greet'
➜  hello git:(greet) git hist
*   7913c56 2025-06-03 | Merged main fixed conflict. (HEAD -> greet) [D3LET3-57]
|\  
| * 1277033 2025-06-03 | Made interactive (main) [D3LET3-57]
* | 58c0382 2025-06-03 | Merge branch 'main' into greet [D3LET3-57]
|\| 
| * 895a1b8 2025-06-03 | Added README [D3LET3-57]
* | cb4831a 2025-06-03 | Updated Rakefile [D3LET3-57]
* | e64c2f8 2025-06-03 | Hello uses Greeter [D3LET3-57]
* | 047fc2b 2025-06-03 | Added a greeter class [D3LET3-57]
|/  
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
#That’s a bit hard to read, but looking at the data we see that the “Updated Rakefile” commit was the last commit on the greet branch before merging. Let’s reset the greet branch to that commit.
➜  hello git:(greet) git reset --hard cb4831a  
HEAD is now at cb4831a Updated Rakefile
➜  hello git:(greet) git hist --all
* 1277033 2025-06-03 | Made interactive (main) [D3LET3-57]
* 895a1b8 2025-06-03 | Added README [D3LET3-57]
| * cb4831a 2025-06-03 | Updated Rakefile (HEAD -> greet) [D3LET3-57]
| * e64c2f8 2025-06-03 | Hello uses Greeter [D3LET3-57]
| * 047fc2b 2025-06-03 | Added a greeter class [D3LET3-57]
|/  
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
The `greet` branch has been reset to the commit before the merge, which is `cb4831a`. The commit history now shows that the `greet` branch is at the same point as it was before the merge, with no merge commits present.
# Lab 33
```bash
➜  hello git:(main) git reset --hard 895a1b8       
HEAD is now at 895a1b8 Added README
➜  hello git:(main) git hist --all 
* 895a1b8 2025-06-03 | Added README (HEAD -> main) [D3LET3-57]
| * cb4831a 2025-06-03 | Updated Rakefile (greet) [D3LET3-57]
| * e64c2f8 2025-06-03 | Hello uses Greeter [D3LET3-57]
| * 047fc2b 2025-06-03 | Added a greeter class [D3LET3-57]
|/  
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
The ‘Added README’ commit is the one directly before the conflicting interactive mode. We will reset the main branch to ‘Added README’ commit.
# Lab 34
```bash
➜  hello git:(main) gco greet 
Switched to branch 'greet'
➜  hello git:(greet) git rebase main 
Successfully rebased and updated refs/heads/greet.
➜  hello git:(greet) git hist       
* 07fb1d7 2025-06-03 | Updated Rakefile (HEAD -> greet) [D3LET3-57]
* 8540dcb 2025-06-03 | Hello uses Greeter [D3LET3-57]
* 9dc4ab9 2025-06-03 | Added a greeter class [D3LET3-57]
* 895a1b8 2025-06-03 | Added README (main) [D3LET3-57]
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
Merge v/s Rebase<br>
The `greet` branch has been successfully rebased onto the `main` branch. The commit history now shows that the commits from the `greet` branch have been applied on top of the `main` branch, creating a linear history without any merge commits. This makes the history cleaner and easier to follow.
# Lab 35
```bash
➜  hello git:(greet) gco main 
Switched to branch 'main'
➜  hello git:(main) gm greet 
Updating 895a1b8..07fb1d7
Fast-forward
 Rakefile       |  3 +--
 lib/greeter.rb |  8 ++++++++
 lib/hello.rb   | 10 ++++++----
 3 files changed, 15 insertions(+), 6 deletions(-)
 create mode 100644 lib/greeter.rb
➜  hello git:(main) git hist
* 07fb1d7 2025-06-03 | Updated Rakefile (HEAD -> main, greet) [D3LET3-57]
* 8540dcb 2025-06-03 | Hello uses Greeter [D3LET3-57]
* 9dc4ab9 2025-06-03 | Added a greeter class [D3LET3-57]
* 895a1b8 2025-06-03 | Added README [D3LET3-57]
* 4dbc382 2025-06-03 | Added a Rakefile [D3LET3-57]
* 20e3e36 2025-06-03 | Moved hello.rb to lib [D3LET3-57]
* 85af29c 2025-06-03 | Add an author/email comment [D3LET3-57]
* 5f9df6a 2025-06-03 | Added a comment (tag: v1) [D3LET3-57]
* 0a4623a 2025-06-03 | Added a default value (tag: v1-beta) [D3LET3-57]
* 0136159 2025-06-03 | Using ARGV [D3LET3-57]
* 8c91514 2025-06-03 | First Commit [D3LET3-57]
```
Because the head of main is a direct ancestor of the head of the greet branch, git is able to do a fast-forward merge. When fast-forwarding, the branch pointer is simply moved forward to point to the same commit as the greeter branch.

There will never be conflicts in a fast-forward merge.
Unlike a merge, rebasing does not create a new commit. Instead, it rewrites the commit history by applying the changes from one branch onto another. This results in a cleaner, linear history without merge commits, making it easier to understand the project’s evolution.

# References
- [Git Immersion](http://gitimmersion.com/)
