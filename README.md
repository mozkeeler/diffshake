diffshake
-----

This should actually probably be called 'shakedump' or something. The original goal was to create a tool that could
compare (i.e. diff) TLS handshake client hello messages from different implementations (or versions, etc.). I soon
realized that the simplest thing would be to just dump the hellos in some sort of text format and use a diff tool to
compare them. Thus, I tend to use this like `vimdiff <(cargo run helloA.bin) <(cargo run helloB.bin)`. I really didn't
put much effort into this other than getting the ~80% functionality I needed, but I thought `tls-parser` was a neat
library and this seemed like a good example of "hey, isn't Rust and the Rust ecosystem neat".

