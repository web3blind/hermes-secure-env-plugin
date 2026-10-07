"""Fixture-owned optional authority; never installed in the host or plugin."""
from pathlib import Path


class OwnershipFixture:
    def __init__(self, home, task, browser, parent):
        self.home = Path(home).resolve()
        self.task, self.browser, self.parent = task, browser, parent
        self.token = 'synthetic-call'
        self.owner, self.generation = 'session:' + task, task
        self.terminal = False

    def proof(self, task, browser, parent, home):
        if Path(home).resolve() != self.home or task != self.task:
            raise ValueError('explicit parent not owned by task')
        if self.terminal or browser != self.browser or parent != self.parent:
            raise ValueError('explicit parent not owned by task')
        return self.owner, self.generation, self.token

    def call(self, token):
        assert token == self.token
        return {'owner': self.owner, 'generation': self.generation}

    def retire(self, owner, generation, *, evidence):
        assert (owner, generation) == (self.owner, self.generation)
        assert evidence == 'synthetic-terminal'
        self.terminal = True
        return True
