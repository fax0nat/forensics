//библиотека ввода-вывода для вывода информации в консоль
#include <iostream>
//библиотека для работа с файлами
#include <fstream>
//вспомогательная библиотека для выравнивания, форматирования вывода и т.д.
#include <iomanip>
//конечно, нам потребуются структуры из Windows.h
//но ничто, в общем-то, не мешает их перенести прямо в код и скомпилировать это под линукс :)
#include <Windows.h>

#include <conio.h>

#define Is2power(x) (!(x & (x - 1)))
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x) 

using namespace std;

int main(int argc, const char* argv[])
{
	//если аргумент не передали - выведем пример использования и выйдем
	if (argc != 2)
	{
		cout << "Usage: sectons.exe pe_file" << endl;
		return 0;
	}

	ifstream pefile;
	pefile.open(argv[1], ios::in | ios::binary);
	if (!pefile.is_open())
	{
		//если вдруг его открыть не удалось, то выведем ошибку и выйдем
		cout << "Can't open file" << endl;
		return 0;
	}

	//определим размер файла, он нам пригодится дальше
	pefile.seekg(0, ios::end);
	//для этого переведем файловый указатель чтения в самый конец файла, получим его позицию
	streamoff filesize = pefile.tellg();
	//это и будет размер файла в байтах
	//затем вернем файловый указатель в начало файла
	pefile.seekg(0);

	IMAGE_DOS_HEADER dos_header;
	pefile.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
	if (pefile.bad() || pefile.eof())
	{
		//если вдруг считать не удалось...
		cout << "Unable to read IMAGE_DOS_HEADER" << endl;
		return 0;
	}

	//Первые два байта структуры должны быть MZ, но, так как в x86 у нас обратный порядок следования байтов,
	//мы сравниваем эти байты со значением 'ZM'
	if (dos_header.e_magic != 'ZM')
	{
		cout << "IMAGE_DOS_HEADER signature is incorrect" << endl;
		return 0;
	}

	//Начало заголовка самого PE-файла (IMAGE_NT_HEADERS) должно быть
	//выровнено на величину двойного слова (DWORD)
	//убедимся, что это так
	if ((dos_header.e_lfanew % sizeof(DWORD)) != 0)
	{
		//а иначе наш PE-файл некорректен
		cout << "PE header is not DWORD-aligned" << endl;
		return 0;
	}

	//Переходим на структуру IMAGE_NT_HEADERS и готовимся считать ее
	pefile.seekg(dos_header.e_lfanew);
	if (pefile.bad() || pefile.fail())
	{
		cout << "Cannot reach IMAGE_NT_HEADERS" << endl;
		return 0;
	}

	//Читаем
	//читать будем только часть структуры IMAGE_NT_HEADERS
	//без дата директорий
	//они нам и не понадобятся сейчас
	IMAGE_NT_HEADERS32 nt_headers;
	pefile.read(reinterpret_cast<char*>(&nt_headers), sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	if (pefile.bad() || pefile.eof())
	{
		cout << "Error reading IMAGE_NT_HEADERS32" << endl;
		return 0;
	}
	//Проверяем, что наш файл - PE
	//сигнатура у него должна быть "PE\0\0"
	//помним про обратный порядок байтов и проверяем...
	if (nt_headers.Signature != 'EP')
	{
		cout << "Incorrect PE signature" << endl;
		return 0;
	}

	//Проверяем, что это PE32
	if (nt_headers.OptionalHeader.Magic != 0x10B)
	{
		cout << "This PE is not PE32" << endl;
		return 0;
	}

	//позиция в файле таблицы секций - это размер всех заголовков полностью
//(включая дос-стаб, если он есть и все дата директории, если они есть)
	DWORD first_section = dos_header.e_lfanew + nt_headers.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;

	//переходим на первую секцию в таблице секций
	pefile.seekg(first_section);
	if (pefile.bad() || pefile.fail())
	{
		cout << "Cannot reach section headers" << endl;
		return 0;
	}

	cout << hex << showbase << left;

	for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++)
	{
		//готовим заголовок секции
		IMAGE_SECTION_HEADER header;
		//и читаем его
		pefile.read(reinterpret_cast<char*>(&header), sizeof(IMAGE_SECTION_HEADER));
		if (pefile.bad() || pefile.eof())
		{
			cout << "Error reading section header" << endl;
			return 0;
		}

		//во-первых, "сырой" размер данных и виртуальный размер секции
		//не могут быть одновременно нулевыми
		if (!header.SizeOfRawData && !header.Misc.VirtualSize)
		{
			cout << "Virtual and Physical sizes of section can't be 0 at the same time" << endl;
			return 0;
		}

		//если размер инициализированных данных ("сырых") не равен нулю...
		if (header.SizeOfRawData != 0)
		{
			//Проверим, что инициализированные данные секции также не вылетают за пределы нашего PE-файла
			if (ALIGN_DOWN(header.PointerToRawData, nt_headers.OptionalHeader.FileAlignment) + header.SizeOfRawData > filesize)
			{
				cout << "Incorrect section address or size" << endl;
				return 0;
			}

			//в этой переменной мы сохраним выровненный виртуальный размер секции
			DWORD virtual_size_aligned;

			//если виртуальный размер секции был выставлен в ноль,
			if (header.Misc.VirtualSize == 0)
				//то ее выровненный виртуальный размер равен ее реальному размеру инициализированных данных,
				//выровненному на границу SectionAlignment
				virtual_size_aligned = ALIGN_UP(header.SizeOfRawData, nt_headers.OptionalHeader.SectionAlignment);
			else
				//а иначе он равен ее виртуальному размеру,
				//выровненному на границу SectionAlignment
				virtual_size_aligned = ALIGN_UP(header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);

			//Проверим, что виртуальное пространство секции не вылетает за пределы виртуального пространства всего PE-файла
			if (header.VirtualAddress + virtual_size_aligned > ALIGN_UP(nt_headers.OptionalHeader.SizeOfImage, nt_headers.OptionalHeader.SectionAlignment))
			{
				cout << "Incorrect section address or size" << endl;
				return 0;
			}
		}

		//имя секции может иметь размер до 8 символов
		char name[9] = { 0 };
		memcpy(name, header.Name, 8);
		//выводим имя секции
		cout << setw(20) << "Section: " << name << endl << "=======================" << endl;
		//ее размеры, адреса
		cout << setw(20) << "Virtual size:" << header.Misc.VirtualSize << endl;
		cout << setw(20) << "Raw size:" << header.SizeOfRawData << endl;
		cout << setw(20) << "Virtual address:" << header.VirtualAddress << endl;
		cout << setw(20) << "Raw address:" << header.PointerToRawData << endl;

		//и самые важные характеристики
		cout << setw(20) << "Characteristics: ";
		if (header.Characteristics & IMAGE_SCN_MEM_READ)
			cout << "R ";
		if (header.Characteristics & IMAGE_SCN_MEM_WRITE)
			cout << "W ";
		if (header.Characteristics & IMAGE_SCN_MEM_EXECUTE)
			cout << "X ";
		if (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			cout << "discardable ";
		if (header.Characteristics & IMAGE_SCN_MEM_SHARED)
			cout << "shared";

		cout << endl << endl;
	}


	return 0;
}

