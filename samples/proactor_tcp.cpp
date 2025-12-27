#include "proactor.hpp"

int main()
{
    Proactor proactor;
    int n = proactor.run("0.0.0.0", 8080);
    return n;
}
