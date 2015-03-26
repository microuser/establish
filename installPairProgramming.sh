#!/bin/sh

yum -y install tmux wemux git

dialog --yesno "Do you want to install wemux" 20 20
if [ $? ]; then
  #https://netguru.co/blog/what-s-a-pair-to-do-pair
  echo "set -g mode-mouse on" >> ~/.tmux.conf
  echo "set -g mouse-resize-pane on" >> ~/.tmux.conf
  echo "set -g mouse-select-pane on" >> ~/.tmux.conf
  echo "set -g mouse-select-window on" >> ~/.tmux.conf
  echo 'set -g default-terminal "screen-256color"' >> ~/.tmux.conf
  echo "set -g history-limit 1000" >> ~/.tmux.conf
fi

dialog --yesno "Do you want to install Vimified" 20 20
if [ $? ]; then
  #Get Vimified
  #https://github.com/zaiste/vimified
  #curl -L https://raw.github.com/zaiste/vimified/master/install.sh | sh
  
  yum -y install git
  cd
  git clone git://github.com/zaiste/vimified.git
  ln -sfn vimified/ ~/.vim
  ln -sfn vimified/vimrc ~/.vimrc
  cd vimified
  mkdir bundle
  mkdir -p tmp/backup tmp/swap tmp/undo
  git clone https://github.com/gmarik/vundle.git bundle/vundle
  echo "let g:vimified_packages = ['general', 'coding', 'clojure', 'color']" > local.vimrc
  vim +BundleInstall +qall

fi
