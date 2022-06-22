#include <stdio.h>
#include <functional>

using namespace std;

typedef function<int(int)> fun;

int square(int num) { return num * num; }
int triple(int num) { return num * 3; }
fun compose(int(f)(int), int(g)(int)) { return [f, g](int x) { return f(g(x)); }; }
fun squareOfTriple = compose(square, triple);

void printResult() {
	printf("squareOfTriple(2) = %d", squareOfTriple(2));
	// Выводит: squareOfTriple(2) = 36
}
