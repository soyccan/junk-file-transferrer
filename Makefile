SUBDIRS := ksocket master_dev slave_dev master slave
.PHONY: $(SUBDIRS)

all: $(SUBDIRS)

ksocket:
	$(MAKE) -C ksocket/src

master_dev:
	$(MAKE) -C master_dev

slave_dev:
	$(MAKE) -C slave_dev

master:
	$(MAKE) -C user_program master

slave:
	$(MAKE) -C user_program slave

ksocket-clean:
	$(MAKE) -C ksocket/src clean

master_dev-clean:
	$(MAKE) -C master_dev clean

slave_dev-clean:
	$(MAKE) -C slave_dev clean

master-clean:
	$(MAKE) -C user_program clean

slave-clean:
	$(MAKE) -C user_program clean

clean: $(SUBDIRS:%=%-clean)
