#!/bin/sh

method=mmap
choice=$1
file=$2

if [ "$choice" = 1 ]; then # 1: small input
    ./user_program/master 10 \
        ./input/sample_input_1/target_file_1 \
        ./input/sample_input_1/target_file_2 \
        ./input/sample_input_1/target_file_3 \
        ./input/sample_input_1/target_file_4 \
        ./input/sample_input_1/target_file_5 \
        ./input/sample_input_1/target_file_6 \
        ./input/sample_input_1/target_file_7 \
        ./input/sample_input_1/target_file_8 \
        ./input/sample_input_1/target_file_9 \
        ./input/sample_input_1/target_file_10 \
        $method &

    nc localhost 8888 >output/1

elif [ "$choice" = 2 ]; then # 2: medium input
    ./user_program/master 1 \
        ./input/sample_input_2/target_file \
        $method &

    nc localhost 8888 >output/2

elif [ "$choice" = 3 ]; then # 3: custom input
    ./user_program/master 1 \
        ./input/$file \
        $method &

    nc localhost 8888 >output/$file

    if ! tail -c+9 output/$file | diff - input/$file; then
        echo output different!
        exit 1
    fi
fi
