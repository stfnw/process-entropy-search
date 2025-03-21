This is a small experiment in identifying potential secrets in process memory by searching for high-entropy strings.
The main thing I learned from this project is, that entropy (based on a uniform probability distribution) alone is not really well suited for distinguishing possible secrets.
For example, with the way calculated here, the following entropy values result for various byte sequences:

    3.618 eesh0ahfaegheingo0uani3ekahsooHikahsheij

    4.756 Cak2zeitieshishoh8ma3quewieYaeCahrooCahvohduY8bohghexu6EucohGhatha5EB2ohwaeghainee5ieYie6Igohtheebohkue9Jieshuisovee3zai1eghiekahcijeigaiRieQu5iegie2meireigahBahghoo5euF0je2Ahf1di1vaefu6Aesh0al9yi7OoceiC9ahHa8aeR3naeph0Xitohs9VieJoreimohbuixeeka7ohMaegae0shoh9Shah4eufey2woofeyo3Choqueicieha9Ee5ohghoom7Uozahquah8Baiy5ahmie3res1cee2azur9eeNoo9Jeigeev0wapharoo5Phai3Lotee3Ao4AXooshae8memaip9euB3aiz5iu

    4.997 WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1.
        (a random string from an instance/process of neovim)

    6.555 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~

# Usage

```
$ cargo run -- --help
Running with arguments: CliArgs { help: PrintUsage, pid: 0, min_length: 8, min_entropy: 5.0 }
Search process memory for high-entropy printable ASCII strings

Usage: process-entropy-search --pid PID [--minlength MINLENGTH] [--minentropy MINENTROPY]

    --pid PID
          Process ID of the process memory to search

    --minlength MINLENGTH
          Search only strings with a length >= MINLENGTH
          Default: MINLENGTH=8

    --minentropy MINENTROPY
          Search only strings where the entropy is >= MINENTROPY
          Default: MINENTROPY=5.0

    --help Show this help text
```

# Demo

```
$ echo '#9vrkf!E"f5H4.9%F$_S' > example.txt
$ less example.txt

$ cargo run -- --pid $(pgrep less) --minentropy 4.0 | head
Running with arguments: CliArgs { help: NormalOperation, pid: 5149, min_length: 8, min_entropy: 4.0 }
Found string with entropy 4.1219 in process less             with pid    5149 at 0x00005A7FF97B1900: "#9vrkf!E"f5H4.9%F$_S"
Found string with entropy 4.0431 in process less             with pid    5149 at 0x00005A80178B5C80: "tmux-256color|tmux with 256 colors"
Found string with entropy 5.0000 in process less             with pid    5149 at 0x00005A80178B5EE8: "++,,--..00``aaffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~"
Found string with entropy 4.0431 in process less             with pid    5149 at 0x00005A80178B7780: "tmux-256color|tmux with 256 colors"
Found string with entropy 5.0000 in process less             with pid    5149 at 0x00005A80178B79E7: "++,,--..00``aaffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~"
Found string with entropy 4.1219 in process less             with pid    5149 at 0x00005A80178BA6E0: "#9vrkf!E"f5H4.9%F$_S"
Found string with entropy 4.0207 in process less             with pid    5149 at 0x00005A80178BBB20: "?n?f%f .?m(%T %i of %m) ..?e(END) ?x- Next\: %x..%t"
Found string with entropy 4.3324 in process less             with pid    5149 at 0x00005A80178BBB60: "?n?f%f .?m(%T %i of %m) ..?e(END) ?x- Next\: %x.:?pB%pB\%:byte %bB?s/%s...%t"
Found string with entropy 4.4174 in process less             with pid    5149 at 0x00005A80178BBBC0: "?f%f .?n?m(%T %i of %m) ..?ltlines %lt-%lb?L/%L. :byte %bB?s/%s. .?e(END) ?x- Next\: %x.:?pB%pB\%..%t"
```
