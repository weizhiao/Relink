extern const int base_points;
extern int points(void);

int score(void) {
    return base_points + points();
}
