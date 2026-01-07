#include "proactor.hpp"
#include "handler.hpp"

int main()
{
    Proactor<Handler_base> proactor;
    int n = proactor.run("0.0.0.0", 8080);
    return n;
}
