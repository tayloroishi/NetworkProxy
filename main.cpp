#include <iostream>
#include "src/reader.h"

int main() {
    std::cout << "Hello, World!" << std::endl;

    auto pcapReader = PacketCapture::Reader();

    pcapReader.Start();
    pcapReader.Run();


    std::cout << "Done" << std::endl;

    return 0;
}
