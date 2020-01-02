int main(int argc, char *argv[]){
  char *args[] = {"/snap/bin/gnome-calculator", 0};
  char *envp[] = {"DISPLAY=:0", 0};
  execve("/snap/bin/gnome-calculator", args, envp);
}
