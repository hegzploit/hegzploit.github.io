---
title: "My new blogging workflow"
date: 2022-02-18
description: "I started blogging at 2020 and was using Hugo as my go-to Static Site Generator, It was pretty fast and did the job well (Jekyll yes, I'm looking you)."
enableToc: false
---

I started blogging at 2020 and was using Hugo as my go-to Static Site Generator, It was pretty fast and did the job well (Jekyll yes, I'm looking you).

The process went as follows:
I had two repos, one for the blog config files and the markdown sources of my posts. I then build these files using `hugo build` into static HTML pages which I push to another repo that serves my blog through github pages.

The process went as follows:
- Pull a fresh copy of my blog config repo
- Create a new .md file with my new blog post
- Commit the changes to my repo and push
- Build the repo to generate the static website
- Push the website to the gh pages serving repo

This process was very boring and sometimes I'd forget to sync my repos across the different machines I use, eventaully I just used dropbox to store the blog config. and .md files but I still wasn't satisfied with my setup.

# New Blogging Workflow

I was searching for any new SSG besides hugo until I found [zola](https://www.getzola.org/) which is very similar to hugo except It's more barebones which is something I liked (rust ftw!), I migrated my posts and started thinking about an easier alternative to my current workflow.

## CI/CD is just fancy make
I'd always hear about this CI/CD jargon and I finally thought it's time to give it a try, It was [surprisingly easy too](https://github.com/shalzz/zola-deploy-action).
It's like make but for the cloud ain't it?

I created my repo with the source code for my blog and some random yaml file which I copy-pasted from the internet and voila!
Now I can just push any new .md file to the repo and It will automatically build and deploy for a gh pages branch for me.

## Endless possibilities
It's not just about deploying with a single push, I can even blog using my browser directly from the web.

[Hackmd](https://hackmd.io/) is a markdown editor for the browser which has github integration, so I can just write my blog there and Github will handle the rest.
![](https://i.imgur.com/0bmACY8.png)

The only downside to this workflow is how Hackmd uses imgur to host images, I wish there'd be an easier approach to have the images self-contained in the repo.

## Update 19/12/2022
I have switched from hackmd to https://github.dev, the integrated vscode gave me a more streamlined experience and I enjoyed my workflow even more.
I have switched back to hugo since I found a really cool theme which had all of the features I wanted, I'm kinda lazy to write my own theme at this point so I keep hopping between different themes I like, let's see for how long I will stick with the current theme.
