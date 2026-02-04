class CommandController:
    def __init__(self, app):
        self.app = app

    def new_project(self) -> None:
        self.app.handle_new_project()

    def open_project(self) -> None:
        self.app.handle_open_project()

    def save_project(self) -> None:
        self.app.handle_save_project()

    def save_project_as(self) -> None:
        self.app.handle_save_project_as()

    def add_requirements(self) -> None:
        self.app.handle_add_requirements()

    def add_tests(self) -> None:
        self.app.handle_add_tests()

    def run_analysis(self) -> None:
        self.app.handle_run_analysis()

    def export_csv(self) -> None:
        self.app.handle_export_csv()

    def exit_app(self) -> None:
        self.app.handle_exit()
