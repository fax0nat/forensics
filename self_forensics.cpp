#include <iostream>
#include <fstream>
#include <Windows.h>

using namespace std;

class classReadPeFile {
	private:
		ifstream methodFile; //метод класса ifstream для чтения файла
		streamoff fileSize; //перменная хранит рамер файла (streamoff - тип данных, который может хранить максимально большой размер файла в ОС)
		IMAGE_DOS_HEADER dosHeader;

		char *fileName; // перменная,в которой хранится значение переданной в качестве аргумента классу
		char ER_MESSAGE[37] = "Something went wrong. Error number "; //константа, содержащая текст выводящийся при ошибке
	
	public:
		classReadPeFile(char *take_argv) {
			fileName = take_argv;
			start();
		};

		void start() {
			methodFile.open(fileName, ios::in | ios::binary); //открываем файл на получене данных и читаем его в бинарном виде

			if (!methodFile) //проверка на ошибки
				cout << ER_MESSAGE << "1" << endl;

			methodFile.seekg(0, ios::end); //преводим файловый указатель в конец файла 
			fileSize = methodFile.tellg(); //возвращает позицию указателя => размер файла
			methodFile.seekg(0); //возвращаем указатель на начало 

			methodFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER)); // начинаем чиатать файл

															/* 
												[ПОЯСНЕНИЯ К СТРОЧКЕ ВЫШЕ]

			istream& read (char* s, streamsize n);
			Read block of data
			Extracts n characters from the stream and stores them in the array pointed to by s.
			Данные файла записываются в структуру IMAGINE_DOS_HEADER.
			(https://www.cplusplus.com/reference/istream/istream/read/)

															*/

			if (methodFile.bad() || methodFile.eof()) //проверка на ошибки
				cout << ER_MESSAGE << "2" << endl;

			//Первые два байта структуры должны быть MZ, но, так как в x86 у нас обратный порядок следования байтов,
			//мы сравниваем эти байты со значением 'ZM'
			if (dosHeader.e_magic != 'ZM')
				cout << ER_MESSAGE << "3" << endl;

			cout << "Value of e_magic: " << dosHeader.e_magic << "\n";
			cout << "Value of e_lfanew: " << dosHeader.e_lfanew << "\n";
			

			methodFile.close();//закрываем файл
		}
};

int main(int argc, char *argv[]) {

	if (argc != 2)
		cout << "You must run this programm from consol. \nExample: program_name pefile.exe \n";
	else
		classReadPeFile s(argv[1]);
	
	//system("pause");
	return 0;
}
