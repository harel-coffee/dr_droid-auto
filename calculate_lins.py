import os


#search tex file under the current directory
#replace files
def iterator_files():
    i = 0
    for file in os.listdir("./"):
        if file.endswith(".py"):
           with open(file, "r") as ins:
                print (file)
                for line in ins:
                    i = i + 1            
    print (i)
           
#repalce the original file with the modified file
def remove_and_replace_files():
    for file in os.listdir("./"):
        if file.endswith(".tex"):
           print ("remove ...." + file)
           os.remove(file)

    for file in os.listdir("./"):
        if file.endswith(".temp"):
           file_new_name = file[0:len(file)-5]
           print (" moving " + file  +"  to  " + file_new_name)
           os.rename(file, file_new_name)


iterator_files()

