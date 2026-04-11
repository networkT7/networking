task install
tmux new -d -s networking
tmux neww
tmux send "task -- wire W1" ENTER
tmux splitw -h
tmux send "task -- wire W2" ENTER
tmux splitw -v
tmux send "task -- wire W3" ENTER
tmux selectp -t networking:1.0
tmux splitw -v
tmux send "task -- router" ENTER

tmux selectw -t networking:0
tmux send "task -- node N1" ENTER
tmux splitw -h
tmux send "task -- node N2" ENTER
tmux splitw -v
tmux send "task -- node N4" ENTER
tmux selectp -t networking:0.0
tmux splitw -v
tmux send "task -- node N3" ENTER


tmux attach -t networking
