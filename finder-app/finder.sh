#!/bin/sh

if [ -z $1 ] || [ -z $2 ]
then
    echo "You must provide two parameetrs. The first parameter must be a directory to search. The second parameter is a string to search"
    exit 1
fi

filesdir=$1
searchstr=$2

if [ ! -d $filesdir ]
then
    echo $filesdir" is not a directory or don't exist"
    exit 2
fi

totalFilesCount=$(ls $filesdir | wc -l)
foundedFilesCount=$(grep -r $2 $filesdir | wc -l)

echo "The number of files are ${totalFilesCount} and the number of matching lines are ${foundedFilesCount}"
