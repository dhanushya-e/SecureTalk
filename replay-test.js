let lastSequence = 2;

function checkSequence(sequence) {
    if (sequence !== lastSequence + 1) {
        console.log("REJECTED: Replay detected!");
        return;
    }

    lastSequence = sequence;
    console.log("ACCEPTED: New message.");
}

checkSequence(3); // Should be accepted
checkSequence(3); // Should be rejected
checkSequence(4); // Should be accepted