# pexp

pexp is a Protable Executable file format parser aiming to study behaviors from a security point of view.

Note that this project is a Work In Progress, things are really early, some features could change a lot and new features can appear too so stay tuned !

## the goal

The number one goal is simply having fun, i'm a security analyst passionned by tooling. One thing i came accross and i don't like at all, for the analysis of PE files, we have some options but there is a low amount of open source tools available and as i want to learn more, i'm trying the journey myself. I really like tools like Detect It Easy but there is some things i want to be more scalable and more adaptable as a command tool. For now it'll be just a print tool like Die as it's not having a lot of functionnality yet. In the future i hope i'll implement a json or xml output for more usefull integration into EDR or SIEM services. One thing that other tools don't do a lot, it's behavior analysis. I don't see it often and the only tools that does that are closed source and really not sourcing their methods which i don't like. Here, i will add everything i'm using for you to see what's going on in the actual tool.

I want to thank the creator of https://github.com/saferwall/pe which i use in my tool. Really nice library, feature rich and simple-stupid.
