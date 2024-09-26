import org.apache.commons.collections.ListUtils;
import java.util.ArrayList;

public class Butler {

    public void welcome() {


        ArrayList<String> list1 = new ArrayList<>();
        list1.add("Hello");
        ArrayList<String> list2 = new ArrayList<>();
        list2.add("World");

        System.out.println(ListUtils.union(list1, list2));
    }
}
