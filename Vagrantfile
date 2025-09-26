IMAGE_NAME = "ubuntu/focal64"
N = 2

Vagrant.configure("2") do |config|

    config.vm.provider "virtualbox" do |v|
        v.memory = 1024
        v.cpus = 1
    end

    config.vm.define "bmv2-1" do |switch|
        switch.vm.box = "viniciussimao/bmv2-p4"
        switch.vm.box_version = "01"
        switch.vm.hostname = "bmv2-1"
        
        #management network (IP - 192.168.56.200)
        switch.vm.network "private_network", ip: "192.168.56.200",
            name: "vboxnet0"
        
        #Internal network between host-1 and bmv2 switch1.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "H1-S1"
        
        #Internal network between bmv2 switches
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S1-H2"


        switch.vm.provider "virtualbox" do |v|
            v.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
            v.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
        end

        switch.vm.provision "ansible" do |ansible| 
            ansible.playbook = "switch-setup/switch-playbook-1.yml"
        end
    end

    config.vm.define "host-0" do |h|
        h.vm.box = IMAGE_NAME
        h.vm.hostname = "host-0"
        h.vm.network "private_network", ip: "192.168.51.1", mac: "0800273a9f12",
            virtualbox__intnet: "H0-H1"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host0-playbook.yml"
        end
    end

    config.vm.define "host-1" do |h|
        h.vm.box = IMAGE_NAME
        h.vm.hostname = "host-1"
        h.vm.network "private_network", ip: "192.168.50.11", mac: "080027600c50",
            virtualbox__intnet: "H1-S1"
        h.vm.network "private_network", ip: "192.168.51.2",
            virtualbox__intnet: "H0-H1"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host1-playbook.yml"
        end
    end

    config.vm.define "host-2" do |h|
        h.vm.box = IMAGE_NAME
        h.vm.hostname = "host-2"
        h.vm.network "private_network", ip: "192.168.50.12", mac: "0800271de027",
            virtualbox__intnet: "S1-H2"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host2-playbook.yml"
        end
    end

end
