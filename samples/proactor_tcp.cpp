#include "proactor.hpp"

int main()
{
    Proactor proactor;
    int n = proactor.run("127.0.0.1", 8080);
    return n;
}
