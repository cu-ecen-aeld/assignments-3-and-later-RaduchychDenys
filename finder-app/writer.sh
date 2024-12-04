
if [ -z "$1" ] || [ -z "$2" ]
then
    echo "You must provide two arguments. First argument is a path to file including filename. Second argument is a content of this file"
    exit 1
fi 

echo $2 > $(pwd)$1
