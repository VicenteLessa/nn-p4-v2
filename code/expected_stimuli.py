import sys

def main(neurons):
    neurons = [int(x) for x in neurons.split(",")]
    expected_stimuli = 0
    for x in neurons:
        expected_stimuli = expected_stimuli | 1 << x

    print("dec:", expected_stimuli)
    print("bin:", bin(expected_stimuli))

if __name__ == '__main__':
    main(sys.argv[1])
