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
NLP has been a target of AI for a very long time, in the following paragraphs we will go through some of the history to get a better context on what we are currently targeting.

Natural languge can be expressed in two main forms
1. Text form
2. Audio form

both of these forms have one thing in common, their output depends on past input. modeling this type of systems is tricky, we need a model that can represent this causal relationship between the input and output.

This is where we start using the recurrent neural network to model our data, the RNN is a type of neural network that has feedback, this is neccessary to model natural languge since the network's output depends on past input.
![](rnn.png)

This network archeticture proved to be problematic when dealing with very large data sizes, this is due to the failure of the model to capture information that is far away from the current word due to the vanishing gradiennt problem[^vanishing_grad]

In 1997 a research paper was published that introduced a new RNN archeticture called the "Long Short-Term Memory" (LSTM), this archeticture dealt with the vanishing gradient problem by introducing a gating mechanism inside the cells of the network, this enables us to control the gradient flow within the cell so we can prevent the gradient from vanishing or exploding.

Up to this point, we could use LSTMs to predict new data from past data, however we had always struggled with sequence to sequence learning, this was a very special task in NLP that involved transforming an input sequence to an output sequence. The most popular sequence to sequence task is machine translation where we transform a sequence of words in a certain language to another sequence of words in another language.

In 2014, researchers from google published a paper that proposed a new network archeticture that could deal with sequence to sequence tasks, The encoder-decoder archeticture.

> The idea is to use one LSTM, the encoder, to read the input sequence one timestep at a time, to obtain a large fixed dimensional vector representation (a context vector), and then to use another LSTM, the decoder, to extract the output sequence from that vector. The second LSTM is essentially a recurrent neural network language model except that it is conditioned on the input sequence.[^seq2seq]
[^seq2seq]: https://paperswithcode.com/method/seq2seq

## Beyond LSTMs: Attention and Transformers
However, even though LSTMs could now capture longer dependencies and perform Seq2Seq tasks, they still struggled with keeping information for very long sequences, this was mainly due to the limited memory of LSTMs and their noise accumulation. 

In 2014 too, a reasearch intern at the Montreal university published a paper where he proposed a new way to approach neural machine translation, The authors proposed a novel approach to address the limitation of the fixed-length context vector in the encoder-decoder architecture. Instead of relying solely on the final hidden state of the encoder, the attention mechanism allows the decoder to adaptively focus on different parts of the input sequence while generating the output sequence. This is done by learning a set of alignment weights between the input and output sequences, he called this new mechanism "Attention" and he achieved state-of-the-art translation performance with his archeticture.

Everything up to this point still used LSTMs which wasn't all that great, we can observe that all the innovation that was done in 2014 was huge and it started adding components to the LSTM, a component for the encoder and decoder, another component for the attention mechanism. all of this was built on top of the trusty old LSTMs from the 97's.

Three years into the future and we are now in 2017, eight researchers from google brain published a diruptive paper in the field of AI, they proposed yet another new archeticture that didn't add upon the LSTM as we have seen lately, instead, it stripped the LSTM component entirely from the network archeticture keeping the encoder-decoder structure and the attention mechanism, they named the paper "Attention is all you need" in which they introduced the "Transformer" archeticture.

This change to the neural network has sol
## LSTM for audio classification
After tedious days of data gathering, cleaning and labeling. we ended up with around 15 minutes of audio data, this seemed so little but we kept going anyway.

We kept experimenting with different model hyperparameters on a validation dataset but every single try showed a sign of overfitting, It became clear that we could no longer progress further with the little data that we have, and hence we started with plan B.

![](overfit.jpg)

## Plan B: Transformers
I was always interested about transformers, I was initially planning to finetune a transcription model like whisper by OpenAI on the little data that I have, but I was very skeptical it would be make any difference If I trained it on 15 minutes, after looking around for the hottest finetuned models for the arabic language I saw the work of ArabML[^arabml] in the whisper fine-tuning event by huggingface, they had finetuned a model that achieved a WER of 12.0 and It was on an arabic dataset of Egyptian dialect[^whisper-model]!

This was exactly what I needed so I started experimenting with the model through the free huggingface inference API, It didn't transcribe the incorrect words very accurately probably due to the normalization that is associated with automatic speech recoginition (ASR) models but It was something I could work with.

I created a list of all the possible wrong words (that has articulation errors) that we will face along with the corresponding correct words, this can be shown from the below image.
![](possible_words.jpg)

After creating this list, we just feed the transcribed text to an algorithm that can find the closest match from our words list, this process is repeated for all the uttered words and we have a list of all the wrong words that was uttered along with their corresponding correct word. the difference between these two words will be the substited letter.
[^whisper-model]: https://huggingface.co/Zaid/whisper-large-v2-ar
[^arabml]: https://arbml.github.io/
[^vanishing_grad]: https://en.wikipedia.org/wiki/Vanishing_gradient_problem
[^attn_is_all_you_need]: https://proceedings.neurips.cc/paper_files/paper/2017/file/3f5ee243547dee91fbd053c1c4a845aa-Paper.pdf
[^darsh]: https://www.linkedin.com/in/mostafa-m-mokthar-7aa2a7192/

