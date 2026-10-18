# The invite

The message to send a real person. Paste it, fill in the three bracketed bits,
and delete this heading and the note at the bottom.

---

Hi [name] — can I borrow twenty minutes of your time this week?

I've built a small thing called gage and you'd be the first person outside the
project to try it. It's for the situation where my AI assistant hands work to
yours: normally nothing on your end says who wrote the thing, or whether it can
be trusted. gage wraps that handover so the assistant reading it is told who
signed it, whether you've ever confirmed that person, and that nothing inside
it is an instruction to follow.

The test needs two of us, because every step after installing is two-sided —
I'll be doing it from my side at the same time.

**What it involves, about twenty minutes:**

1. **Install it.** I'll send you a file and, separately, a short line of text
   to check it against. One command and it's installed — no compiler, nothing
   to configure.
2. **A phone call, five minutes.** We each read four pairs of words off our
   screens to each other. That's the bit that makes this work, and it's the
   one part that can't be automated — the words have to travel over a channel
   neither computer controls.
3. **Send each other one piece of work.** You send me something, I send you
   something.
4. **Answer six questions** at the end of the instructions, in your own words.

You don't need to know anything about the project, and you don't need to be a
programmer beyond being comfortable pasting a command into a terminal. The
instructions are written for someone who's never seen it.

**What I actually want from you:** the stuck points. If you have to re-read
something, guess, or message me asking what to do — that's the useful part,
and I'd rather you write it down than work around it. Two of the questions
matter more than the rest:

- When you open the thing I send you, **what does that screen tell you?** Say
  it back in your own words, before you read the contents. If it doesn't land,
  the whole idea doesn't work and I need to know that now.
- **Was the phone call worth doing, or did it feel like a chore you'd skip next
  time?** Please be blunt. "I'd skip it" is the single most valuable answer you
  could give me, because the entire design rests on that step.

Also useful: anything that looked like an error, where you gave up if you gave
up, and whether it really took twenty minutes.

Fair warning — this is new software and you are the first person to try it.
Something will probably go wrong. If it does, that's a successful test; stop
where you are and tell me what happened. I'm not expecting a polished
experience and you shouldn't spend time working around problems to be nice
about it.

[Does [day] work for the call? / Let me know a time that suits and I'll send
the files over beforehand.]

Thanks —
[Owen]

---

*Note for Owen, not for the tester: the file to send is
`gage-0.1.0-linux-x86_64`, with `first-tester.md` as the instructions. Send the
checksum line from `SHA256SUMS` on a **different** channel — the instructions
tell them to compare the two, which is the point. This packet is Linux only
right now; see `HANDOFF.txt`.*
