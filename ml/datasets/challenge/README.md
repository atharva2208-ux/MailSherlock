# Challenge set

A small, hand-written set of **modern** emails used only for evaluation, never
for training or threshold selection.

The legitimate training corpus (SpamAssassin ham) dates from 2002 and is
dominated by mailing-list traffic. It does not contain the transactional mail
that causes most real-world false positives: password resets, verification
codes, security alerts, receipts, delivery notifications, and marketing.
This set measures how the classifier behaves on exactly those messages.

All messages are fictional and were written for this project. Because it is
small (22 legitimate, 12 phishing) its metrics have wide confidence intervals
and are reported as raw counts, not as a headline accuracy figure.
