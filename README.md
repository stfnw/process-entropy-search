This is a small experiment in identifying potential secrets in process memory by searching for high-entropy strings.
The main thing I learned from this project is, that entropy (based on a uniform probability distribution) alone is not really well suited for distinguishing possible secrets.
For example, with the way calculated here, the following entropy values result for various byte sequences:

    3.618 eesh0ahfaegheingo0uani3ekahsooHikahsheij

    4.756 Cak2zeitieshishoh8ma3quewieYaeCahrooCahvohduY8bohghexu6EucohGhatha5EB2ohwaeghainee5ieYie6Igohtheebohkue9Jieshuisovee3zai1eghiekahcijeigaiRieQu5iegie2meireigahBahghoo5euF0je2Ahf1di1vaefu6Aesh0al9yi7OoceiC9ahHa8aeR3naeph0Xitohs9VieJoreimohbuixeeka7ohMaegae0shoh9Shah4eufey2woofeyo3Choqueicieha9Ee5ohghoom7Uozahquah8Baiy5ahmie3res1cee2azur9eeNoo9Jeigeev0wapharoo5Phai3Lotee3Ao4AXooshae8memaip9euB3aiz5iu

    4.997 WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1.
        (a random string from an instance/process of neovim)

    6.555 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~

# Usage

TODO

# Demo

TODO
