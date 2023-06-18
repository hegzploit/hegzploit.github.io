---
title:  "An Electrical Engineer's Adventure into the Deep Dark of AI"
date:  2023-06-18
draft:  true
enableToc: true
description: "I talk about AI in the context of my graduation project."
tags:
- misc
image: "images/thumbnails/gp.jpeg"
libraries:
- katex
---

## Introduction
Artificial Intellegince has been prevalent lately, this can be accounted for many reasons but the most important is Moore's Law, the amount of compute power availiable to the average user let alone big corporations such as Microsoft and Facebook is way more than what we could get in the 90's.

This becomes clear when we observe the nature of the current state-of-the art trends in AI, the Transformer model which was proposed by Vaswani et al.[^attn_is_all_you_need] in 2017 rids of any feedback connections (RNNs) and only utilizes what they called "self-attention". This operation is highly-parallelizable and can exploit the large number of cores in modern GPUs.

{{< notice info "Modern GPUs" >}}
A popular GPU that is widely used in AI is the Nvidia A100 which has 6912 CUDA cores, It's successor the H100 has 18,432 CUDA cores!
{{< /notice >}}

## Overview of the project
Our project addresses the problem of articulation disorders diagnosis in the Arabic language, we take a multimodal approach to solve this problem, we first identify whether the disorder is of a physiological nature or not, this is achieved through a binary image classifier that is trained on public pictures of patients with hare lip, we only chose hare lip for our prototype due to its abundance of data.

Once the patient has been classified to have an abnormality we do nothing further, on the other hand, If the patient doesn't have a physiological disorder then we proceed to the second stage of the pipeline which is the audio analysis phase. In this phase the patient utters mutliple words in a microphone that feeds into an LSTM model to further classify the patient's articulation disorder (Lisp, Rhotacism, ...), the model was trained on data that we gathered locally.

After the articulation disorder has been classified, the patient undergoes a written questionnaire that identifies whether the disorder could be due to psychological or social reasons.

The following picture shows an overview of the first iteration of our project (yes this is a hint that we did a second iteration).

![](general_diagram.png)

I will focus on the audio pipeline in this blog post, the image pipeline was the work of my dear friend Mostafa[^darsh].

## NLP in AI
NLP is a very old problem, It involves the modeling of human speech into a form understandable by computers, after getting our audio into a state that is easy to work with, we need a way classify this audio which is of temporal nature (varies in time), hence we decomposed our problem into a classification problem, but the problem with data that has a temporal nature is it's causal nature.

{{< notice info "Causal Systems" >}}
A causal system is one whose output depends only on the present and the past inputs.
{{< /notice >}}

A very special type of neural networks was born for this reason, the recurrent neural netowork. There is no one man behind inventing the RNNs but It was most likely all built upon the Ising model which is a mathematical model of ferromagnetism in statistical mechanics, this model consisted of variables that can represent magnetic dipole moments that can be in one of two states (+1 or -1), It also arranged the dipole moments in a graph, this represention is very similar to artificial neural networks that model the neurons in the brain, a neuron can have one of two states (active or inactive) and each neuron is connected to neighbouring neurons in a graph-like structure.
[^attn_is_all_you_need]: https://proceedings.neurips.cc/paper_files/paper/2017/file/3f5ee243547dee91fbd053c1c4a845aa-Paper.pdf
[^darsh]: https://www.linkedin.com/in/mostafa-m-mokthar-7aa2a7192/
